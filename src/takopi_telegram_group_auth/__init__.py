from __future__ import annotations

from .backend import TelegramGroupAuthBackend

BACKEND = TelegramGroupAuthBackend()

__all__ = ["BACKEND", "TelegramGroupAuthBackend"]
