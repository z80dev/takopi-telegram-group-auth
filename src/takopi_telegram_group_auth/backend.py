from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator

import anyio
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from takopi.api import (
    ConfigError,
    ExecBridgeConfig,
    MessageRef,
    RenderedMessage,
    SendOptions,
    SetupIssue,
    SetupResult,
    TransportBackend,
    TransportRuntime,
)
from takopi.backends_helpers import install_issue
from takopi.config import HOME_CONFIG_PATH
from takopi.logging import get_logger
from takopi.settings import TelegramFilesSettings, TelegramTopicsSettings, load_settings
from takopi.telegram.bridge import (
    TelegramBridgeConfig,
    TelegramCallbackQuery,
    TelegramFilesConfig,
    TelegramIncomingMessage,
    TelegramIncomingUpdate,
    TelegramPresenter,
    TelegramTopicsConfig,
    TelegramTransport,
    TelegramVoiceTranscriptionConfig,
    poll_updates,
    run_main_loop,
)
from takopi.telegram.client import TelegramClient, is_group_chat_id
from takopi.settings import require_telegram_config

logger = get_logger(__name__)


@dataclass(frozen=True)
class GroupAuthConfig:
    deny_message: str | None
    cache_ttl_s: float
    group_chat_id: int | None


class GroupAuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth_cache_ttl_s: float = 60.0
    deny_message: str | None = None
    group_chat_id: int | None = None

    @field_validator("auth_cache_ttl_s", mode="before")
    @classmethod
    def _validate_cache_ttl(cls, value):
        if value is None:
            return 60.0
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("auth_cache_ttl_s must be a number")
        if value < 0:
            raise ValueError("auth_cache_ttl_s must be >= 0")
        return float(value)

    @field_validator("deny_message", mode="before")
    @classmethod
    def _validate_deny_message(cls, value):
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("deny_message must be a string")
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("deny_message must be a non-empty string")
        return cleaned

    @field_validator("group_chat_id", mode="before")
    @classmethod
    def _validate_group_chat_id(cls, value):
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("group_chat_id must be an integer")
        return value


def _build_auth_config(
    transport_config: dict[str, object], *, config_path: Path
) -> GroupAuthConfig:
    raw: dict[str, object] = {}
    if "auth_cache_ttl_s" in transport_config:
        raw["auth_cache_ttl_s"] = transport_config["auth_cache_ttl_s"]
    if "deny_message" in transport_config:
        raw["deny_message"] = transport_config["deny_message"]
    if "group_chat_id" in transport_config:
        raw["group_chat_id"] = transport_config["group_chat_id"]
    try:
        settings = GroupAuthSettings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid auth config in {config_path}: {exc}") from exc
    return GroupAuthConfig(
        deny_message=settings.deny_message,
        cache_ttl_s=settings.auth_cache_ttl_s,
        group_chat_id=settings.group_chat_id,
    )


@dataclass(frozen=True)
class _AdminCacheEntry:
    expires_at: float
    is_admin: bool


class _AdminChecker:
    def __init__(self, *, bot: TelegramClient, cache_ttl_s: float) -> None:
        self._bot = bot
        self._cache_ttl_s = max(0.0, cache_ttl_s)
        self._cache: dict[tuple[int, int], _AdminCacheEntry] = {}

    async def is_admin(self, chat_id: int, user_id: int) -> bool:
        now = time.monotonic()
        if self._cache_ttl_s > 0:
            entry = self._cache.get((chat_id, user_id))
            if entry is not None and entry.expires_at > now:
                return entry.is_admin
        member = await self._bot.get_chat_member(chat_id, user_id)
        is_admin = (
            isinstance(member, dict)
            and member.get("status") in {"creator", "administrator"}
        )
        if self._cache_ttl_s > 0:
            self._cache[(chat_id, user_id)] = _AdminCacheEntry(
                expires_at=now + self._cache_ttl_s,
                is_admin=is_admin,
            )
        return is_admin


def _is_group_chat(update: TelegramIncomingUpdate) -> bool:
    if isinstance(update, TelegramIncomingMessage):
        if update.chat_type is not None:
            return update.chat_type in {"group", "supergroup"}
    return is_group_chat_id(update.chat_id)


async def _deny_update(
    cfg: TelegramBridgeConfig,
    update: TelegramIncomingUpdate,
    *,
    message: str | None,
) -> None:
    if isinstance(update, TelegramCallbackQuery):
        await cfg.bot.answer_callback_query(
            update.callback_query_id,
            text=message,
            show_alert=False if message else None,
        )
        return
    if message is None:
        return
    reply_to = MessageRef(
        channel_id=update.chat_id,
        message_id=update.message_id,
    )
    await cfg.exec_cfg.transport.send(
        channel_id=update.chat_id,
        message=RenderedMessage(text=message, extra={}),
        options=SendOptions(
            reply_to=reply_to,
            notify=False,
            thread_id=update.thread_id,
        ),
    )


async def _allow_update(
    cfg: TelegramBridgeConfig,
    update: TelegramIncomingUpdate,
    *,
    auth_cfg: GroupAuthConfig,
    checker: _AdminChecker,
) -> bool:
    is_group = _is_group_chat(update)
    if auth_cfg.group_chat_id is not None and is_group:
        if update.chat_id != auth_cfg.group_chat_id:
            return False
    if not is_group:
        return True
    sender_id = update.sender_id
    if sender_id is None:
        await _deny_update(cfg, update, message=auth_cfg.deny_message)
        return False
    try:
        is_admin = await checker.is_admin(update.chat_id, sender_id)
    except Exception as exc:
        logger.warning(
            "group_auth.check_failed",
            chat_id=update.chat_id,
            sender_id=sender_id,
            error=str(exc),
        )
        await _deny_update(cfg, update, message=auth_cfg.deny_message)
        return False
    if is_admin:
        return True
    await _deny_update(cfg, update, message=auth_cfg.deny_message)
    return False


async def _poll_updates_with_auth(
    cfg: TelegramBridgeConfig,
    *,
    auth_cfg: GroupAuthConfig,
) -> AsyncIterator[TelegramIncomingUpdate]:
    checker = _AdminChecker(bot=cfg.bot, cache_ttl_s=auth_cfg.cache_ttl_s)
    async for update in poll_updates(cfg):
        if await _allow_update(cfg, update, auth_cfg=auth_cfg, checker=checker):
            yield update


def _build_startup_message(
    runtime: TransportRuntime,
    *,
    startup_pwd: str,
) -> str:
    available_engines = list(runtime.available_engine_ids())
    missing_engines = list(runtime.missing_engine_ids())
    engine_list = ", ".join(available_engines) if available_engines else "none"
    if missing_engines:
        engine_list = f"{engine_list} (not installed: {', '.join(missing_engines)})"
    project_aliases = sorted({alias for alias in runtime.project_aliases()}, key=str.lower)
    project_list = ", ".join(project_aliases) if project_aliases else "none"
    return (
        "\N{OCTOPUS} **takopi is ready**\n\n"
        f"default: `{runtime.default_engine}`  \n"
        f"agents: `{engine_list}`  \n"
        f"projects: `{project_list}`  \n"
        f"working in: `{startup_pwd}`"
    )


def _build_voice_transcription_config(
    transport_config: dict[str, object],
) -> TelegramVoiceTranscriptionConfig:
    return TelegramVoiceTranscriptionConfig(
        enabled=bool(transport_config.get("voice_transcription", False)),
    )


def _build_topics_config(
    transport_config: dict[str, object],
    *,
    config_path: Path,
) -> TelegramTopicsConfig:
    raw = transport_config.get("topics") or {}
    if not isinstance(raw, dict):
        raise ConfigError(
            f"Invalid `transports.telegram_group_auth.topics` in {config_path}; "
            "expected a table."
        )
    try:
        settings = TelegramTopicsSettings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid topics config in {config_path}: {exc}") from exc
    return TelegramTopicsConfig(
        enabled=settings.enabled,
        scope=settings.scope,
    )


def _build_files_config(
    transport_config: dict[str, object],
    *,
    config_path: Path,
) -> TelegramFilesConfig:
    raw = transport_config.get("files") or {}
    if not isinstance(raw, dict):
        raise ConfigError(
            f"Invalid `transports.telegram_group_auth.files` in {config_path}; "
            "expected a table."
        )
    try:
        settings = TelegramFilesSettings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid files config in {config_path}: {exc}") from exc
    return TelegramFilesConfig(
        enabled=settings.enabled,
        auto_put=settings.auto_put,
        uploads_dir=settings.uploads_dir,
        allowed_user_ids=frozenset(settings.allowed_user_ids),
        deny_globs=tuple(settings.deny_globs),
    )


def _display_path(path: Path) -> str:
    home = Path.home()
    try:
        return f"~/{path.relative_to(home)}"
    except ValueError:
        return str(path)


def _config_issue(path: Path, *, title: str) -> SetupIssue:
    return SetupIssue(title, (f"   {_display_path(path)}",))


class TelegramGroupAuthBackend(TransportBackend):
    id = "telegram_group_auth"
    description = "Telegram bot (group admin auth)"

    def check_setup(
        self,
        engine_backend,
        *,
        transport_override: str | None = None,
    ) -> SetupResult:
        issues: list[SetupIssue] = []
        config_path = HOME_CONFIG_PATH
        cmd = engine_backend.cli_cmd or engine_backend.id
        if shutil.which(cmd) is None:
            issues.append(install_issue(cmd, engine_backend.install_cmd))
        try:
            settings, config_path = load_settings()
            if transport_override:
                settings = settings.model_copy(update={"transport": transport_override})
            config = settings.transport_config(self.id, config_path=config_path)
            require_telegram_config(config, config_path)
        except ConfigError:
            issues.append(
                _config_issue(
                    config_path,
                    title="configure telegram_group_auth transport",
                )
            )
        return SetupResult(issues=issues, config_path=config_path)

    def interactive_setup(self, *, force: bool) -> bool:
        _ = force
        return False

    def lock_token(
        self, *, transport_config: dict[str, object], config_path: Path
    ) -> str | None:
        token, _ = require_telegram_config(transport_config, config_path)
        return token

    def build_and_run(
        self,
        *,
        transport_config: dict[str, object],
        config_path: Path,
        runtime: TransportRuntime,
        final_notify: bool,
        default_engine_override: str | None,
    ) -> None:
        watch_enabled = False
        try:
            settings, _ = load_settings(config_path)
        except ConfigError as exc:
            logger.warning(
                "config.watch.disabled",
                error=str(exc),
            )
        else:
            watch_enabled = settings.watch_config

        token, chat_id = require_telegram_config(transport_config, config_path)
        startup_msg = _build_startup_message(
            runtime,
            startup_pwd=os.getcwd(),
        )
        bot = TelegramClient(token)
        transport = TelegramTransport(bot)
        presenter = TelegramPresenter()
        exec_cfg = ExecBridgeConfig(
            transport=transport,
            presenter=presenter,
            final_notify=final_notify,
        )
        voice_transcription = _build_voice_transcription_config(transport_config)
        topics = _build_topics_config(transport_config, config_path=config_path)
        files = _build_files_config(transport_config, config_path=config_path)
        auth_cfg = _build_auth_config(transport_config, config_path=config_path)
        extra_chat_ids: tuple[int, ...] | None = None
        if auth_cfg.group_chat_id is not None and auth_cfg.group_chat_id != chat_id:
            extra_chat_ids = (auth_cfg.group_chat_id,)
        cfg = TelegramBridgeConfig(
            bot=bot,
            runtime=runtime,
            chat_id=chat_id,
            startup_msg=startup_msg,
            exec_cfg=exec_cfg,
            voice_transcription=voice_transcription,
            topics=topics,
            files=files,
            chat_ids=extra_chat_ids,
        )

        async def run_loop() -> None:
            await run_main_loop(
                cfg,
                poller=lambda cfg: _poll_updates_with_auth(cfg, auth_cfg=auth_cfg),
                watch_config=watch_enabled,
                default_engine_override=default_engine_override,
                transport_id=self.id,
                transport_config=transport_config,
            )

        anyio.run(run_loop)


BACKEND = TelegramGroupAuthBackend()
