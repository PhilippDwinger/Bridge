# Bridge

Universal communication layer: programs in any language (Python, Java, Lua/Roblox, ...) talk to each other
through Bridge servers over plain HTTP + JSON. Bridge servers can be connected, so a client on one server can
reach clients and realms on another one.

Everything lives in RAM. When a server stops, all clients, messages and realms are gone.

## Start a server

```python
import bridge
from bridge import ConnectionMode

app = bridge.Bridge("0.0.0.0", 8000, password="admin-password", public_url="https://bridge.example.com")
app.add_trusted_server("admin-password", "https://other-bridge.example.com")
app.start_server(ConnectionMode.UNSAFE)   # SAFE = TLS with localhost+2.pem / localhost+2-key.pem
```

Or `python main.py` with the environment variables `BRIDGE_PASSWORD`, `BRIDGE_PUBLIC_URL`, `BRIDGE_TRUSTED`, `PORT`.

`public_url` is the address clients and other servers use to reach this server. It is part of every client IP and
realm address, so it must be the real public URL.

## Addresses

```
<server url><|BRIDGE_IP_SPLIT|><id>
https://bridge.example.com<|BRIDGE_IP_SPLIT|>9f2c4e...
```

Client IPs and realm addresses use this format. The part before the separator shows which server the address
belongs to. Because the URL is unique, every address is unique across all Bridge servers.

A client also has a **client key**. It is only used inside its own server and is never sent out.

## Requests and errors

Every endpoint is `POST` with a JSON object as body (except `GET /server/status` and `GET /realm/public`).
Client endpoints need `"session_token"` in the body.

Errors come back with an HTTP status and:

```json
{"detail": {"error": "MAILBOX_FULL", "name": "Mailbox Full", "message": "The recipient's mailbox is full. Try again later."}}
```

`error` is stable and meant for code. All ids are listed in `bridge/errors/exceptions.py`.

## Clients

| Endpoint | Body | Answer |
|---|---|---|
| `/client/register` | `name`, `password` | `client_ip` |
| `/client/login` | `client_ip`, `password` | `session_token`, `expires_at`, `remaining_minutes` |
| `/client/logout` | `session_token` | |
| `/client/me` | `session_token` | `client_ip`, `name`, `realms` |

Sessions last 60 minutes. After 5 failed logins the caller is locked for 5 minutes.

## Messages

`/message/send` takes `recipient_ip` and `content` (any JSON). Optional fields:

- `mode`: `"safe"` (default) or `"fast"`
- `content_type`: `"task"` (default) or `"response"`
- `conversation_id` and `causation_id`

It answers with `message_id` and `conversation_id`. The recipient can be on another trusted server.

| Mode | How it works |
|---|---|
| **fast** | Max 64 KiB. `/message/poll` returns the whole `content` and the message is deleted right away. No hash, no retry. |
| **safe** | Max 1 MiB. `/message/poll` returns `pending_id` and metadata (`sha256`, `chunk_count`). The message is only deleted after the hash was confirmed. |

### Receiving a safe message

1. `/message/poll` returns `pending_id` and `message.sha256` / `message.chunk_count`.
2. `/message/chunk` with `pending_id` and `chunk_index` (0 to chunk_count-1). Join all chunks in order.
3. Hash the UTF-8 bytes of the joined text with SHA-256 (hex). The joined text is JSON, so decode it to get the content.
4. `/message/complete` with `pending_id` and `sha256`. If the hash is right, the message is deleted. If not, you get `HASH_MISMATCH` and the message stays.
5. `/message/cancel` with `pending_id` puts the message back into the mailbox. Without complete or cancel, it goes back by itself after 15 minutes.

Poll order: instruction > response > task. Messages expire after 10 minutes. Clients cannot send instructions.

To answer, send a message with `content_type: "response"` to the sender. Use `causation_id` = the id of the
message you are answering and the same `conversation_id`.

## Realms

All realm actions work the same for realms on your own server and on trusted servers: you always send them to
your own server.

| Type | Join | Host commands | Call commands |
|---|---|---|---|
| public | free | everyone | everyone |
| protected | access key or invitation code | members (only the owner if `restricted_to_owner`) | members |
| private | access key or code, both give roles | owner + roles with `can_host_commands` | owner + members with one of `allowed_roles` (empty = all members) |

| Endpoint | Body (besides `session_token`) |
|---|---|
| `GET /realm/public` | – (public realm of this server) |
| `/realm/create` | `realm_type`, `realm_name`, optional: `access_key` and `restricted_to_owner` (protected) |
| `/realm/join` | `realm_address`, `access_key` or `code` |
| `/realm/leave` | `realm_address` |
| `/realm/info` | `realm_address` |
| `/realm/kick` | `realm_address`, `member_ip` (owner) |
| `/realm/transfer` | `realm_address`, `new_owner_ip` (owner) |
| `/realm/code/create` | `realm_address`, `expires_in_minutes`, optional: `roles`, `preferred_code` (owner) |
| `/realm/command/create` | `realm_address`, `command_name`, optional: `allowed_roles` |
| `/realm/command/remove` | `realm_address`, `command_name` |
| `/realm/role/create` | `realm_address`, `role_name`, optional: `can_host_commands` (private, owner) |
| `/realm/role/set` | `realm_address`, `member_ip`, `roles` (private, owner) |
| `/realm/key/create` | `realm_address`, optional: `roles`, `preferred_key` (private, owner) |

## Commands

`/command/call` takes `command_name`. Optional fields:

- `command_args`
- `realm_address` (without it, Bridge searches the public realm and every realm you are in)
- `mode`

Bridge picks the least busy host and sends it a `task` message with this content:

```json
{"command_name": "add", "command_args": [2, 3], "realm_address": "..."}
```

The host answers with a normal `response` message. The call returns `message_id` and `host_ip`.

## Connecting Bridge servers

Two servers only talk to each other when **both** admins added the other URL:

1. Each admin calls `/admin/trusted/add` (or `Bridge.add_trusted_server`).
2. The servers do a handshake automatically.
3. The handshake creates a secret token that protects every later server-to-server request.

A server can only forward messages of its own clients, and only to clients of the other server. There is no relaying
through a third server.

| Endpoint | Body |
|---|---|
| `/admin/status` | `password` |
| `/admin/trusted/list` | `password` |
| `/admin/trusted/add` | `password`, `url` |
| `/admin/trusted/remove` | `password`, `url` |
| `/admin/trusted/connect` | `password`, `url` (start the handshake again) |
| `/admin/reset` | `password` (removes clients, messages, realms; keeps trusted servers) |
| `/admin/password/change` | `password`, `new_password` |

Use https in production. The handshake secret and all tokens travel over the connection.

## Tests

```
python tests/e2e_two_servers.py
```

The test starts two real servers and checks all flows: messages, realms, commands, trust, restart and brute force.
