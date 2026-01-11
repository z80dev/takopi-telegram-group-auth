# takopi-telegram-group-auth

Telegram transport plugin for Takopi that only responds to group admins.

## Install

```sh
pip install takopi-telegram-group-auth
```

## Configure

Set the transport to `telegram_group_auth` and configure the transport section:

```toml
transport = "telegram_group_auth"

[transports.telegram_group_auth]
bot_token = "..."
chat_id = -123456789

auth_cache_ttl_s = 60
# deny_message = "admins only"

[transports.telegram_group_auth.topics]
enabled = true
scope = "auto"

[transports.telegram_group_auth.files]
enabled = true
auto_put = true
```

### Options

- `auth_cache_ttl_s` (float, default `60`): cache duration for admin checks.
- `deny_message` (string, optional): reply text sent to non-admins in group chats.

## Notes

This transport wraps Takopi's Telegram implementation and uses internal
modules, so it is tied to Takopi's minor version compatibility.
