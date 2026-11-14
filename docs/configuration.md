# Configuration

LANChat reads `config.toml`, written by the setup wizard on first launch.
Every key, with its default, is listed in
[configs/lanchat.example.toml](../configs/lanchat.example.toml) (a test keeps
that file in sync with the code).

```sh
lanchat config path        # where the file is
lanchat config show        # effective configuration (defaults included)
lanchat config edit        # open in $VISUAL / $EDITOR, then validate
lanchat config validate    # check without starting
lanchat --setup            # rerun the wizard, keeping your identity and data
```

Keys missing from the file use defaults; unknown keys are reported as
warnings. LANChat never rewrites the file on upgrade — only the wizard and the
`/theme` and `/bell` commands save it.

## Locations

| | macOS | Linux | Windows |
|---|---|---|---|
| Config | `~/Library/Application Support/LANChat/config.toml` | `$XDG_CONFIG_HOME/lanchat/config.toml` (`~/.config/lanchat`) | `%APPDATA%\LANChat\config.toml` |
| Identity key, database, lock | `~/Library/Application Support/LANChat/` | `$XDG_DATA_HOME/lanchat/` (`~/.local/share/lanchat`) | `%LOCALAPPDATA%\LANChat\` |
| Logs | `~/Library/Logs/LANChat/` | `$XDG_STATE_HOME/lanchat/` | `%LOCALAPPDATA%\LANChat\logs\` |
| Downloads | `~/Downloads/LANChat` (if `~/Downloads` exists, else `<data>/downloads`) | same | same |

`--home DIR` or `LANCHAT_HOME=DIR` puts everything under `DIR` (`config.toml`,
`DIR/data`, `DIR/logs`) — useful for a second profile on the same machine.
Directories are created with mode 0700 and secrets with 0600 on Unix.

## Reference

### `[user]`
| Key | Default | Description |
|---|---|---|
| `display_name` | wizard | Shown to others. 1–32 characters, no control characters. Not unique. |
| `device_name` | host name | Helps tell devices apart. 1–64 characters. |

### `[network]`
| Key | Default | Description |
|---|---|---|
| `mode` | `"auto"` | `"auto"` or `"managed"` (requires `discovery.managed_server`). |
| `interface` | `"auto"` | `"auto"` uses every suitable LAN interface (virtual/VPN/container adapters excluded); or a name from `lanchat network interfaces`. |
| `listen_address` | `""` | Empty = all addresses of the enabled families on one socket. |
| `port` | `47777` | TCP port, 1024–65535 (0 = random, for tests). |
| `enable_ipv4`, `enable_ipv6` | `true` | At least one must be true. |
| `connection_timeout_seconds` | `10` | TCP connect + TLS + hello, 1–120. |
| `heartbeat_interval_seconds` | `15` | A silent peer is offline after 3×, 2–300. |
| `max_connections` | `64` | Total sessions, 2–1024. |

### `[discovery]`
| Key | Default | Description |
|---|---|---|
| `mdns_enabled` | `true` | Announce and browse `_lanchat._tcp.local.` |
| `refresh_interval_seconds` | `30` | Maximum interval between discovery rounds (queries start at 1 s). |
| `managed_server` | `""` | `host:port` of a `lanchat-discovery` server. |
| `managed_server_fingerprint` | `""` | Server SPKI SHA-256 (`lanchat-discovery fingerprint`). Recommended. |
| `managed_ca_file` | `""` | Alternative to the fingerprint: PEM CA bundle. |
| `static_peers` | `[]` | `"host:port"` entries to dial directly (for networks without multicast). |

At least one discovery method must be enabled.

### `[security]`
| Key | Default | Description |
|---|---|---|
| `tls_enabled` | `true` | Must be `true`; `false` is rejected. |
| `require_peer_approval` | `true` | Must be `true`; `false` is rejected. |
| `allow_pairing_requests` | `true` | `false` declines every incoming pairing request (you can still start pairing yourself). |
| `max_untrusted_sessions` | `16` | Simultaneous connections from unpaired peers. |

### `[chat]`
| Key | Default | Description |
|---|---|---|
| `save_history` | `true` | `false`: messages are kept only while LANChat runs and deleted on exit. |
| `max_message_bytes` | `16384` | Largest message you send (hard limit 65536). |
| `queue_offline_messages` | `true` | Queue direct/group messages for offline paired peers; `false` fails them immediately. |
| `offline_queue_ttl_hours` | `168` | Queued messages fail after this long. |
| `max_queued_per_peer` | `500` | Further messages to an offline peer fail. |
| `max_retry_attempts` | `20` | Sends before a message is marked failed. |

### `[transfer]`
| Key | Default | Description |
|---|---|---|
| `download_dir` | `""` | Where received files go (default above). |
| `max_file_size_mb` | `4096` | Larger offers are declined automatically. |

### `[notifications]`, `[ui]`, `[keys]`, `[storage]`, `[logging]`
`notifications.enabled|bell|peer_events`; `ui.theme` (`dark`, `light`,
`minimal`, `monochrome`), `ui.time_format` (`24h`/`12h`), `ui.mouse` (wheel
scrolling; disables the terminal's own selection); `[keys]` lists of key names
for `send`, `newline`, `command_palette`, `search`, `conversations`,
`refresh`, `next_panel`, `prev_panel`, `help`, `quit` (names as reported by
the terminal, e.g. `ctrl+p`, `alt+enter`, `shift+enter`, `f1`);
`storage.database` (path); `logging.level` (`debug`…`error`), `logging.file`,
`logging.max_size_mb`, `logging.max_files`.

`Shift+Enter` is distinguishable from `Enter` only in terminals that support
keyboard enhancements (kitty protocol, Windows Terminal); `Alt+Enter` and
`Ctrl+J` work everywhere.

## Examples

Office network where multicast is blocked between floors, with a managed
discovery server:

```toml
[network]
mode = "managed"

[discovery]
managed_server = "chat-directory.corp.lan:47780"
managed_server_fingerprint = "3f2a91c0…(64 hex digits)…"
```

Two machines on different subnets that can route to each other:

```toml
[discovery]
static_peers = ["10.20.0.15:47777"]
```
