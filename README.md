# Bridge

Universal communication layer: programs in any language (Python, Java, Lua/Roblox, ...) talk to each other
through Bridge servers over plain HTTP + JSON. Bridge servers can be connected, so a client on one server can
reach clients and realms on another one.

Everything lives in RAM, nothing is written to disk. To survive restarts, a server keeps an **encrypted backup at
its trusted servers** and gets it back after a (re)start (see "Backup").

## Principle: pull only

Bridge never sends anything to a client by itself. Every exchange is a request of the client (`POST`/`GET`) and the
answer to it. Even "real-time" works this way: with `wait_seconds` a client's poll stays open until something
arrives (long polling) – it is still the client's own request.

## Modes at a glance

| Where | Modes |
|---|---|
| Message transport (`mode`) | `fast` (one piece, deleted when polled) · `safe` (chunks + SHA-256, deleted after confirmation) · `compressed` (like safe, packed with zlib) · `temporary` (one piece, deleted after its lifetime) |
| Times (lifetime, planned sending) | timer `..._in_seconds` · point `..._at` (ISO 8601 with offset, or without + `timezone`) |
| Planned time already over (`if_past`) | `send` (default, sent at once + warning) · `reject` (`SEND_TIME_PASSED`) |
| Polling (`wait_seconds`) | `0` = answer at once · `1..25` = wait for the next message |
| Command call | `wait_seconds` `0` = response comes into the mailbox · `>0` = response directly in the answer of the call |
| Host choice (`strategy`) | `least_busy` (default) · `random` · `fastest` (BridgeAgent) – hosts with recent requests are preferred |
| Progress of a task (`progress`) | `off` (default, the host's progress is dropped) · `latest` (only the newest waits) · `all` |
| Argument check (host, `validate`) | `strict` (wrong arguments -> 400) · `warn` (sent with a hint) · `off` |
| Client identity | random IP (default) · stable IP with `identity_secret` (same IP after every restart) |
| Who may send me direct messages | `everyone` · `allowlist` · `nobody` + `block` list |
| Relaying (server setting) | `relay_mode`: `trusted` · `off` and `accept_relayed`: `true` · `false` |
| Backup (server setting) | `backup_mode`: `peers` · `off` |
| BridgeAgent (server setting) | `agent_mode`: `learn` · `frozen` (estimates, no learning) · `off` |
| Conversations (server setting) | `conversation_mode`: `all` (every message with a conversation id) · `started` (only `/conversation/start`) · `off` |
| Conversation recording | `record`: `metadata` (default) · `full` (also the contents) |
| Ways between servers (server setting) | `routing`: `direct` (default) · `agent` (BridgeAgent finds the best way around broken or slow lines) |
| BridgeFriends (server setting) | `friends_mode`: `open` (own, trusted and neutral servers) · `trusted` · `local` · `off` |
| Friend invitation | name (memorable, password required, lives until deleted) · code (random, expires, used once) – `accept`: `auto` · `manual` |
| Own presence for friends | `available` · `busy` · `away` · `invisible` (friends see offline) |

## Start a server

Needs Python 3.13 with `fastapi`, `uvicorn`, `argon2-cffi`, `httpx` and `cryptography` (for the backup).

```python
import bridge
from bridge import ConnectionMode

app = bridge.Bridge("0.0.0.0", 8000, password="admin-password", public_url="https://bridge.example.com")
app.add_trusted_server("admin-password", "https://other-bridge.example.com")
app.start_server(ConnectionMode.UNSAFE)   # SAFE = TLS with localhost+2.pem / localhost+2-key.pem
```

Or `python main.py` with the environment variables `BRIDGE_PASSWORD`, `BRIDGE_PUBLIC_URL`, `BRIDGE_TRUSTED`,
`BRIDGE_BLOCKED`, `PORT`. Without `BRIDGE_PASSWORD` a random password is made for this start and printed once (there is
no fixed default password).

`app.stop_server()` stops the server normally from another thread, like Ctrl+C: waiting long polls answer right away
(empty) and the last backup is sent. This also works on Windows, where a program cannot send Ctrl+C to another process.

`public_url` is the address clients and other servers use to reach this server. It is part of every client IP and
realm address, so it must be the real public URL.

### Reserved path `/site`

`/site` (and everything below it) is reserved for a **website next to the server**: a host app such as BridgeControll
can serve a website under `<server url>/site/` on the same public URL (Tailscale Funnel: `/` → Bridge, `/site` → the
website). No Bridge route may ever start with `/site` – the server refuses to start if one does
(`bridge/server/routes/site.py`). Without a website, Bridge answers `/site/` itself with a small "no website assigned"
page. The admin dashboard (`/admin`) has a **Website** button that opens `/site/`.

## Addresses

```
<server url><|BRIDGE_IP_SPLIT|><id>
https://bridge.example.com<|BRIDGE_IP_SPLIT|>9f2c4e...
```

Client IPs and realm addresses use this format. The part before the separator shows which server the address
belongs to. Because the URL is unique, every address is unique across all Bridge servers.

Server URLs are always written the same way: lower case, without the default port (`https://x:443` = `https://x`),
without a dot at the end of the host and without `/` at the end. Host names must be ASCII (use the `xn--` form for
names with umlauts).

A client also has a **client key**. It is only used inside its own server and is never sent out.

## Requests and errors

Every endpoint is `POST` with a JSON object as body (except `GET /server/status` and `GET /realm/public`).
Client endpoints need `"session_token"` in the body.

Errors come back with an HTTP status and:

```json
{"detail": {"error": "MAILBOX_FULL", "name": "Mailbox Full", "message": "The recipient's mailbox is full. Try again later."}}
```

`error` is stable and meant for code. All ids are listed in `bridge/errors/exceptions.py`.
Some errors add `"details"` for you, e.g. `{"problems": ["args.a: expected number, got string"]}`.

## Clients

| Endpoint | Body | Answer |
|---|---|---|
| `/client/register` | `name`, `password`, optional `identity_secret` (32+ characters) | `client_ip`, `stable_identity` |
| `/client/login` | `client_ip`, `password` | `session_token`, `expires_at`, `remaining_minutes` |
| `/client/logout` | `session_token` | |
| `/client/delete` | `session_token`, `password` | `deleted` – the client removes itself for good (realms, topics, commands, mailbox) |
| `/client/me` | `session_token` | `client_ip`, `name`, `realms`, `direct_policy` |
| `/client/direct` | `session_token`, optional `mode` (`everyone`/`allowlist`/`nobody`), `allow`, `block` | the direct message settings |

**Stable identity:** a client that registers with an `identity_secret` always gets the same IP from this server –
also after a restart without backup (register again with the same secret). Keep the secret like a password.

**Direct message settings:** `allow` and `block` contain client IPs or whole server URLs. `block` always wins.

Limits:

- **Sessions:** last 60 minutes. A client has at most 20 sessions – every login makes a new one, the oldest goes.
- **Login:** 5 failed logins for one account from one address, or 20 for any accounts from one address, lock that
  address for 5 minutes. Attempts are counted before the password check (parallel requests cannot get around it), and a
  right login only clears the counter of its own account.
- **Per server:** max 10 000 clients. When the server is full, clients without any request for 7 days are removed to make room. A removed client leaves its realms, the realms it owns on this server are removed, and its planned messages are not sent anymore.
- **Per caller address:** max 30 registrations per hour.

## Message types

| Type | Who creates it | Verified |
|---|---|---|
| `direct` | any client, to any client (also on other trusted servers) | **no** – the receiver decides what to trust |
| `task` | only Bridge, after the realm allowed a command call | yes |
| `response` | only the host that received the task, only to the caller, only once | yes |
| `progress` | only the host of a task, only to the caller, only until the response – and only if the caller accepted it | yes |
| `instruction` | only the server itself | yes |
| `event` | only Bridge, when a member publishes to a topic of a realm (see "Topics") | yes |
| `friend` | only between friends (BridgeFriends) – both servers check the friendship | yes |

Every message has `"verified": true/false` in its metadata. The `sender_ip` is always set by the sender's home
server, so it cannot be faked. The content of a direct message can be anything.

Each type has its own pool in the mailbox. Poll order: instruction > response > progress > task > event > friend > direct.

## Messages

`/message/send` sends a **direct** message. It takes `recipient_ip` and `content` (any JSON). Optional fields:

- `mode`: `"safe"` (default), `"fast"`, `"compressed"` or `"temporary"`
- `conversation_id` and `causation_id` (without `conversation_id` Bridge starts a new conversation)
- a lifetime: `expires_in_seconds` or `expires_at` (see "Times")
- planned sending: `send_in_seconds` or `send_at`, and `if_past` (see "Planned messages")

It answers with `message_id`, `conversation_id`, `state` (`sent` or `scheduled`), `expires_at` and `warnings`.
Bridge finds the recipient by its IP, also on other trusted servers.
One sender can have at most 100 direct messages and 16 MB waiting in the same mailbox (a mailbox holds max 64 MB).

| Mode | How it works |
|---|---|
| **fast** | Max 64 KiB. `/message/poll` returns the whole `content` and the message is deleted right away. No hash, no retry. |
| **safe** | Max 1 MiB. `/message/poll` returns `pending_id` and metadata (`sha256`, `chunk_count`). The message is only deleted after the hash was confirmed. |
| **compressed** | Like safe, but Bridge packs the content (zlib). Up to 8 MiB before packing, max 1 MiB packed. The metadata has `"encoding": "zlib+base64"` – see "Receiving a safe message". Good for big, repetitive data (text, JSON lists). |
| **temporary** | Like fast (max 64 KiB, one piece), but a lifetime is **required** (max 7 days). After it the message is deleted from the mailbox automatically – also if nobody polled it. |

### Times

Every time can be given in two ways:

- as a timer: `expires_in_seconds: 90`
- as a point in time: `expires_at: "2026-11-01T09:00:00+01:00"` (ISO 8601 with offset or `Z`), or
  `expires_at: "2026-11-01T09:00:00"` plus `timezone: "Europe/Berlin"` (IANA name – summer time is handled)

A point without any timezone is rejected with `TIMEZONE_MISSING` – Bridge never guesses. For the same reason a
local time that does not exist (clocks jump forward in spring) or exists twice (autumn) is rejected – give the offset then. Bridge answers always in
UTC (`+00:00`). Without a lifetime a message lives 10 minutes. On Windows the server needs the package `tzdata` for
timezone names (it is in `pyproject.toml`).

### Planned messages

With `send_in_seconds` or `send_at` (+ `timezone`) the message is sent later by the server (max 30 days ahead,
max 1000 planned per client, together at most 64 MB per client and 1 GB per server). The answer has
`"state": "scheduled"` and `scheduled_for`.

- **Mode temporary** needs its own lifetime also when it is planned.
- **Time already over:** `if_past: "send"` (default) sends it at once and the answer has a warning in `warnings`;
  `if_past: "reject"` answers `SEND_TIME_PASSED`.
- **Lifetime:** a timer counts from the send time. Without a lifetime the 10 minutes start when it is really sent.
- `/message/scheduled` lists the planned messages of the client (`in_seconds`, `send_at`, ...) and the results of the
  last sent ones (`recent_results`: `sent`, `expired`, `failed`, `late_by_seconds`).
- `/message/scheduled/cancel` with `message_id` cancels one.
- `/message/status` shows `scheduled` until it is sent. Planned messages are part of the backup.

### Broadcast

`/message/broadcast` sends the same message to up to 100 clients: `recipients` (list of client IPs), `content` and
the same optional fields as `/message/send`. The content is packed only once. All copies share one `broadcast_id`
and one `conversation_id`. The answer lists every recipient with its `state` (or `error`) and counts `sent`,
`scheduled` and `failed` – one blocked recipient does not stop the others.

`/message/poll` takes two optional fields:

- `content_types`, e.g. `["direct"]` or `["task", "response"]`, to poll only some pools.
- `wait_seconds` (max 25): if nothing is there, the request waits until a message arrives or the time is over.

`/message/status` with `message_id` tells the sender what happened to its message: `waiting`, `taken`, `delivered`
or `expired` (for 60 minutes, also across servers; relayed messages show `unknown`).

### Receiving a safe message

1. `/message/poll` returns `pending_id` and `message.sha256` / `message.chunk_count`.
2. `/message/chunk` with `pending_id` and `chunk_index` (0 to chunk_count-1). Join all chunks in order.
3. **compressed only** (`message.encoding` is `"zlib+base64"`): the joined text is packed – base64-decode it and
   unpack it with zlib (= the original UTF-8 JSON text).
   Hash the UTF-8 bytes of the (unpacked) text with SHA-256 (hex). The text is JSON, so decode it to get the content.
4. `/message/complete` with `pending_id` and `sha256`. If the hash is right, the message is deleted. If not, you get `HASH_MISMATCH` and the message stays.
5. `/message/cancel` with `pending_id` puts the message back into the mailbox. Without complete or cancel, it goes back by itself after 15 minutes.

Messages expire after 10 minutes if nobody polls them (or after their own lifetime).

### Many messages per poll

`/message/poll` with `"max_messages": 1..100` answers `{"messages": [...], "count"}` – every item looks like the
answer of a normal poll. It takes one-piece messages (fast / temporary) one after the other; a safe or compressed
message ends the batch (fetch its chunks first). With `wait_seconds` it waits for the first one as usual. Made for
clients with a request budget, e.g. Roblox game servers (500 HTTP requests per minute) that get many small events.
Without `max_messages` the answer is the same as always.

### Publish inside a poll

`/message/poll` can also take `"publish": [...]` – up to 10 topic publishes, each like `/realm/topic/publish`
(`realm_address`, `topic`, `content`, optional `mode`, `include_self`). They are done first, then the poll runs as
usual. The answer gets `"published"` with one result per entry; a failed entry has `{"topic", "error"}` and does not
stop the others or the poll. So a client with a request budget sends its newest state and gets the others' in ONE
request (Roblox: 7 player updates per second in both directions instead of 3–4). The Roblox extension does this by
itself with `PublishLatest`; an older Bridge server answers without `published`, then it publishes separately.

## Conversations

Like a stream in Wireshark: all messages with the same `conversation_id` in order – who, when, how big, which way,
when taken. Bridge records them on the servers of the involved clients.

| Endpoint | Body | Answer |
|---|---|---|
| `/conversation/start` | `session_token`, optional `title`, `record` (`metadata`/`full`), `participants` (client IPs) | the conversation with its `conversation_id` |
| `/conversation/list` | `session_token`, optional `limit` | the conversations of the client (newest first) |
| `/conversation/stream` | `session_token`, `conversation_id`, optional `after_seq`, `wait_seconds`, `content_types` | `entries`, `last_seq`, `stats` |
| `/conversation/close` | `session_token`, `conversation_id` (only who started it) | nothing is recorded anymore |

- **Entries:** `seq`, `time`, `type`, `mode`, `from`, `to`, `size_bytes`, `state` (`sent` → `waiting` → `taken` →
  `delivered` / `expired` / `failed` / `dropped`), `route` (`local`, `remote:<server>`, `relay`, `relay:<server in the middle>`; with routing `agent` also `direct`),
  `taken_after_s`, `causation_id`, `broadcast_id` and with `record: full` also `content`.
- **Follow live:** call `/conversation/stream` with `after_seq` = the last `last_seq` and `wait_seconds` (max 25) –
  the request waits for new entries (pull only, like long polling).
- **Who sees what:** every client sees only the entries it sent or received. A conversation with `participants` is a
  group: the participants see all entries.
- **Statistics** (`stats`): messages, bytes, per type / state / way, duration, average time until taken.
- **Limits:** 500 entries per conversation (the oldest go), 500 conversations per client, 20 000 per server,
  contents max 2 MiB per conversation and 256 MB per server. Without activity a conversation is forgotten after 24 hours.

## Realms

All realm actions work the same for realms on your own server and on trusted servers: you always send them to
your own server.

| Type | Join | Host commands | Call commands |
|---|---|---|---|
| public | free | everyone | everyone |
| protected | access key or invitation code | members (only the owner if `restricted_to_owner`) | members |
| private | access key or code, both give roles | owner + roles with `can_host_commands` | owner + members with one of `allowed_roles` (empty = all members) |

### Invitation codes

- **Format:** 8 characters, easy to type, e.g. `K7M3XQ9P`. Codes are generated without 0/O and 1/I/L. Upper/lower case and a dash (`k7m3-xq9p`) don't matter.
- **Scope:** a code is unique on its server, so joining needs **only the code**. Add `server_url` if the realm is on another server.
- **Lifetime:** default 60 minutes, at least 1 minute, max 30 days. The owner can limit the uses with `max_uses` and choose an own code with `preferred_code` (8 letters/digits). A `preferred_code` that is already taken counts like a wrong code (otherwise it could be used to find codes).
- **Brute force protection:** after 5 wrong codes/access keys a client is locked for 5 minutes. Only a right code or key resets the counter (joining a public realm does not). After 50 wrong ones from all clients of one *other* server, that whole server is locked – the own clients are counted one by one.

| Endpoint | Body (besides `session_token`) |
|---|---|
| `GET /realm/public` | – (public realm of this server) |
| `/realm/create` | `realm_type`, `realm_name`, optional: `access_key` and `restricted_to_owner` (protected) |
| `/realm/join` | `realm_address` + `access_key` **or** just `code` (+ `server_url`) |
| `/realm/leave` | `realm_address` |
| `/realm/info` | `realm_address` |
| `/realm/kick` | `realm_address`, `member_ip` (owner) |
| `/realm/transfer` | `realm_address`, `new_owner_ip` (owner) |
| `/realm/code/create` | `realm_address`, optional: `expires_in_minutes`, `max_uses`, `roles`, `preferred_code` (owner) |
| `/realm/command/create` | `realm_address`, `command_name`, optional: `allowed_roles`, `description`, `signature` (see "BridgeExpress") |
| `/realm/commands` | `realm_address` – catalog of all commands you may call, with host count, descriptions and signature (`source`: `mirror` = from the synced copy) |
| `/realm/topic/subscribe` | `realm_address`, `topic` |
| `/realm/topic/unsubscribe` | `realm_address`, `topic` |
| `/realm/topic/publish` | `realm_address`, `topic`, `content`, optional `mode` (default `fast`) |
| `/realm/command/remove` | `realm_address`, `command_name` |
| `/realm/role/create` | `realm_address`, `role_name`, optional: `can_host_commands`, `can_publish` (private, owner) |
| `/realm/role/set` | `realm_address`, `member_ip`, `roles` (private, owner) |
| `/realm/key/create` | `realm_address`, optional: `roles`, `preferred_key` (private, owner) |

## Commands

1. **Call:** `/command/call` takes `command_name`. Optional fields:
   - `command_args`
   - `realm_address` (without it, Bridge searches the public realm and every realm you are in)
   - `mode`
   - `strategy`: `least_busy` (default), `random` or `fastest` (shortest estimated time, see "BridgeAgent").
     Hosts that made a request in the last 2 minutes are preferred.
   - `wait_seconds`: wait up to this long for the answer. It then comes directly in `response`; otherwise it lands in the mailbox.
   - `progress`: `off` (default), `latest` or `all` – see "Progress".

   Bridge picks a host and sends it a `task` message with this content:

   ```json
   {"command_name": "add", "command_args": {"a": 2, "b": 3}, "realm_address": "...",
    "accepts_progress": false, "progress_mode": "off"}
   ```

   With a signature and `validate: warn` the task also has `"validation_problems": [...]`.

   The call returns `task_id` and `host_ip`.
2. **Answer:** the host answers with `/command/respond` and the fields `task_id`, `content` and optionally `mode`. The caller gets a `response` message with `causation_id` = `task_id`. A task can be answered once, within 60 minutes.
3. **Checks:**
   - If the task comes from another server, the host's server checks the realm again before it delivers the task.
   - The caller's server only accepts a response for a task it really sent.
   - A client can have at most 1000 calls waiting for an answer, and a host at most 1000 tasks it did not answer yet
     (then `MAILBOX_FULL`).
   - If a host loses the right to host (role taken away, owner changed in a protected realm with `restricted_to_owner`),
     its hosted commands are removed.

### Progress

Long tasks can report intermediate states – but only if the caller wants them:

- The caller sets `progress` on `/command/call`: `off` (default), `latest` (only the newest progress waits in the
  mailbox, older ones are replaced; the response removes it) or `all` (every progress, max 50 per task).
- The host sees `accepts_progress` in the task and sends `/command/progress` with `task_id`, `content` and optionally
  `percent` (0–100). Max 4 KiB, max 5 per second and task.
- If the caller did not accept progress, Bridge simply drops it: the host gets `{"delivered": false}`, no error.
- The caller gets `progress` messages (verified, `causation_id` = `task_id`) with the content `{"percent", "content"}`.
  After the response no more progress is possible.

## BridgeExpress (typed commands)

A host can give a command a **signature** when it hosts it (`/realm/command/create` with `signature`):

```json
{"params": [{"name": "a", "type": "number", "description": "first number"},
            {"name": "level", "type": "integer", "optional": true}],
 "returns": "number",
 "validate": "strict"}
```

Type notation: `number` `integer` `string` `boolean` `nil` `any` · `list<T>` · `map<T>` (text keys) ·
`{name: string, level?: integer}` · `T | U` · `"fire"` (exactly this text) · `(T)` for grouping.

- With a signature, `command_args` are an **object with the parameter names**: `{"a": 2, "level": 3}`.
- `validate` (chosen by the host): `strict` (default) – wrong arguments -> `400 ARGS_INVALID` with
  `details.problems`, the task is not sent, and a response that does not fit `returns` is rejected for the host
  (`400 RESPONSE_INVALID`, the task stays open); `warn` – the task is sent with `validation_problems`; `off` – only information.
- All hosts of a command need the same signature (`409 SIGNATURE_MISMATCH`). A host without a signature takes the existing one.
- The size of the arguments is checked first. A check looks at most at 200 000 values (long union types over huge lists
  would otherwise block the server) – more is refused as "too big to check".
- Signatures of realms on other servers are built again from their texts (a type tree of another server is never used
  as it came).

`/express/schema` (optional `realm_address`, `if_version`) returns every command the client may call: its own
server's public realm and all its realms, with signatures. Every type comes as text **and** as a ready tree
(`type_tree`, `returns_tree`), so an extension does not need its own parser. With `if_version` = the last `version`
the answer is just `{"changed": false}` if nothing changed. Each extension turns the schema into the types of its
language (e.g. typed functions with autocomplete in Roblox Studio) – Bridge itself writes no code.

## BridgeAgent (estimates from experience)

Every server learns from its own traffic – only times, sizes and queue lengths, never contents – and estimates:

| Endpoint | Body | Answer |
|---|---|---|
| `/agent/estimate` | `command_name`, optional `realm_address`, `command_args` | per host: way there, waiting, processing, total (`typical_s`, `worst_s`), queue, reliability; `recommended_host`, `recommended_wait_seconds` |
| `/agent/task` | `task_id` (a task you called) | `state` (`waiting` with `position` / `processing` with `processing_since_s` / `answered`), `progress_percent`, `remaining`, `risk_of_expiry` |
| `/agent/message` | `recipient_ip` | is the recipient active, last seen, how fast it takes messages (only if it accepts direct messages from you) |

- **Model:** a small online regression per host / command / client (in log space) plus a learned 90 % bound
  ("worst" = 9 of 10 cases are faster). New samples count more; if something changes a lot (a host gets much slower),
  the model notices it and re-learns within a few samples.
- **Baseline:** `bridge/subservices/bridge_agent/baseline.json` holds start values, made by `python tools/train_agent.py`
  (real servers with simulated hosts and callers). Each server starts from it and keeps learning on its own.
- **Backup:** what the agent learned is part of the encrypted backup at the trusted servers.
- **More:** `strategy: fastest`, reliability per host (tasks that expire without an answer), anomalies
  ("much slower than usual"), load per hour. Admins see everything with `/admin/agent`; `action: export` gives a new
  baseline.json, `action: reset` starts again from the baseline.

## BridgeFriends (friendships)

Two clients become friends with a memorable name and a password – also when their servers do not trust each other
("neutral": not trusted, not blocked). Then they can talk, and see each other's status.

```
At home:   /friends/invite {"name": "paddy-home", "password": "sonnenblume"}
           -> address paddy-home@bridge.example.com
At school: /friends/add {"address": "paddy-home@bridge.example.com", "password": "sonnenblume"}
           -> friends (state "active")
```

| Endpoint | Body | Answer |
|---|---|---|
| `/friends/invite` | optional `name`, `password`, `label` (my name for friends), `accept` (`auto`/`manual`), `max_uses`, `expires_in_seconds` / `expires_at` (+ `timezone`) | the invitation with its `address` |
| `/friends/invites` · `/friends/invite/delete` | – · `invite_id` | own invitations |
| `/friends/add` | `address` (`name@server`, `CODE@server`, or only the name for this server), `password`, optional `label` | the friend (`state` `active` or `pending_out`) |
| `/friends/requests` · `/friends/answer` | – · `friend_ip`, `accept` (true/false) | open requests (`incoming`, `outgoing`) |
| `/friends/list` · `/friends/info` | – · `friend_ip` | friends with status, and the own presence (`me`) |
| `/friends/remove` · `/friends/nickname` | `friend_ip` (+ `nickname`) | |
| `/friends/presence` | optional `presence`, `status_text` (up to 100 characters) | the own presence |
| `/friends/send` | `friend_ip`, `content` + everything of `/message/send` (mode, times, conversation_id) | like `/message/send` |
| `/friends/broadcast` | `content`, optional `friend_ips` (default: all active friends) | like `/message/broadcast` |

- **Invitations ("doors"):** a **name** (3–32 characters `a-z 0-9 . _ -`, password with at least 6 characters, lives
  until deleted) or a **code** (8 characters like realm codes, may be typed with `-` and small letters, default 60 min,
  used once, password optional). `accept: manual` = the owner answers each request with `/friends/answer`.
- **The password never leaves the server it was typed on.** The door's server keeps only
  `K0 = argon2id(password, salt)`. Who wants to come in gets a challenge (`nonce` + `salt`). Its own server computes
  `K0`, picks its own random `client_nonce` and computes `K1 = argon2id(K0, salt2)` with
  `salt2 = sha256("bridge-friends-k1|<door server>|<door>|<asking client>|<client_nonce>")`, then sends
  `HMAC-SHA256(K1, "bridge-friends-v2|<door server>|<door>|<asking client>|<nonce>|<client_nonce>")`. So a wrong server
  (typo in the address) only gets a proof that costs two argon2 per guessed password – and it cannot precompute a
  dictionary, because the second step depends on the asking server's random value.
- **Guessing:** 5 wrong passwords per asking client, 20 per asking server (15 min, only for other servers) and 100 per
  hour in total per door. An unknown name answers exactly like a wrong password (`FRIEND_INVITE_INVALID`) – same
  challenge, same work, same lock – nobody can find out which names exist.
- **Servers that do not trust each other** make a limited *friend connection*: the same handshake as for trusted servers
  (the server with the smaller URL delivers a secret, the other one calls it back at its URL to confirm). Its token only
  opens `/s2s/friends/*`. Trusted servers use their normal connection. A public server does not make friend connections
  to addresses that are not public (private, local, carrier NAT, ...) or that cannot be resolved. Errors of another
  server reach our clients only from a fixed list (otherwise `REMOTE_SERVER_ERROR`).
- **Nobody can fake a friend:** friend messages have the type `friend` (`verified: true`). Both servers check that the
  friendship is active and that the sender is a client of the server that delivered it. `/s2s/message` does not take
  friend messages. Each friendship has a `safety_code` (12 digits) – both friends see the same and can compare.
- **Status** (in `/friends/list` and `/friends/info`, pulled from the friend's server):
  - `online`: `active` (request in the last 120 s) · `idle` (15 min) · `offline` · `unreachable`
  - `presence` and `status_text`; `invisible` looks `offline` to friends
  - `speed`: `fast` · `normal` · `slow` with `reasons`: the line between the servers (`line_ms`), how fast the friend takes
    messages (BridgeAgent, `pickup_typical_s`) and how many of your messages wait there (`waiting_from_you`)
- **Notifications** come as `instruction` from the own server: `friend_added`, `friend_request`, `friend_declined`,
  `friend_removed` (with `friend_ip`, `label`, `server`, `via`).
- `via` of a friend: `local` · `trusted` · `neutral` · `blocked`.
- **Block list** (admin): `/admin/blocked/add|remove|list` or `Bridge.block_server()` / env `BRIDGE_BLOCKED`. A blocked
  server gets no friendships and no friend connection, and its relayed messages are refused. It is blocked by host and
  port (`https://evil.example/x` = `https://evil.example:443`). Trusted servers cannot be blocked (remove the trust first).
- **Limits:** 500 friends and 20 invitations per client, 10 friend requests and 10 invitations per minute per client.
- Friendships, invitations (only `K`), presence and the block list are part of the backup.
- Without https someone in the network can read along – use https in production.

## Topics (publish/subscribe)

Members subscribe to a topic of a realm. When someone publishes, every subscriber gets an `event` message with the
content `{"realm_address", "topic", "data"}` – on any trusted server. Subscribers fetch events with
`/message/poll` like every other message.

| Realm | Subscribe | Publish |
|---|---|---|
| public | everyone | everyone |
| protected | members | members (only the owner if `restricted_to_owner`) |
| private | members | owner + roles with `can_publish` |

`/realm/topic/publish` takes `realm_address`, `topic`, `content`, optional `mode` (default `fast`) and
`include_self` (default `true`): with `false` a publisher that subscribed the topic itself does not get its own event.

## Connecting Bridge servers

Two servers only talk to each other when **both** admins added the other URL:

1. Each admin calls `/admin/trusted/add` (or `Bridge.add_trusted_server`).
2. The servers do a handshake automatically.
3. The handshake creates a secret token that protects every later server-to-server request.

A server can only forward messages of its own clients, and only to clients of the other server.

### Realm sync

Realm states are the same on every server that has members in the realm:

- The server a realm lives on is the only truth. Every realm has a `version` that goes up with every change. Only
  servers that have members in a realm get its version or copy – others do not even learn that it exists.
- After a change it tells every server with members right away. Those servers keep a copy: only their own members
  with roles, their catalog and topics – never access keys or invitation codes.
- Every 15 seconds the servers also compare the versions and fetch what they missed (e.g. after being offline).
  A late old push cannot bring back a copy that was already removed.
- So a kick on one server removes the realm from the member's `/client/me` on its own server at once, and catalogs and
  `/express/schema` come from the local copy.
- If the realm server cannot be reached, `/realm/info` and `/realm/commands` answer from the copy with `"stale": true`.
  `/client/me` shows `realm_details` (name, type, version, stale) for every realm.

### Relaying

If A trusts B and B trusts C, but A and C do not trust each other, a **direct message** from A to C goes over B:

- A asks its trusted servers to pass it on.
- B does this if its `relay_mode` is `trusted`, and only to servers B trusts itself.
- C accepts it if `accept_relayed` is `true`. The message then carries `"relayed_via": ["<B>"]`.

Only one server in the middle is allowed. Trust is **not** passed on: tasks, responses, events and realm actions still
need direct trust, because C cannot check over B whether something really comes from A.

### Best way (routing)

With `routing` `agent` the BridgeAgent chooses the way to another server:

- Every 15 seconds the servers exchange their line tables (`/s2s/links`): latency, reliability, errors in a row.
- The cost of a way is time / reliability. A line with 3 or more errors in a row is avoided.
- If the direct line is broken or slow, the message goes over a trusted server in the middle (one hop, the other
  server must allow relaying). If one way fails, the next one is tried (max 3).
- `/admin/routes` shows the own lines, the tables of the partners and the best ways to every server.

### Analysis

`/admin/analysis` shows how the server is doing:

- requests per endpoint (last minute, last hour, since start) and errors
- timings (p50 / p90 / p99 / max)
- how much compression saved
- the fullest mailboxes, lines, conversations and planned messages
- accuracy of the BridgeAgent

It runs always and costs almost nothing. Server-to-server requests of 4 KiB or more travel gzip compressed, answers of
1 KiB or more too (if the client accepts gzip).

### Backup

With `backup_mode` `peers` (default) the server sends an encrypted snapshot of everything in RAM to its connected
trusted servers. It does this every 30 seconds when something changed, and once more when it shuts down normally.
The snapshot contains clients, sessions, mailboxes, realms, codes and open tasks.

- **Encryption:** AES-256-GCM. The key is derived from the Bridge password, so the other servers only keep data they cannot read.
- **Restore:** after a start, the server waits up to 15 seconds for all its trusted servers, fetches the newest backup and restores it – only if the server is still empty. Meanwhile clients and other servers get `SERVER_STARTING` (try again).
- **After a password change:** old backups cannot be decrypted anymore, so a new one is sent right away.
- **Limits:** max 50 MB per backup – if it is bigger, the backup is sent without the mailbox contents (`without_messages`). Backups of other servers are kept for 24 hours.
- **Restore problems:** if the newest backup cannot be used, the older ones are tried. If none works – or a trusted server could not be asked – the server goes on empty and keeps the backups at the others: state `paused`, no automatic backup overwrites them. An admin resumes with `/admin/backup/now` (or `/admin/backup/restore`).
- **Normal shutdown** = Ctrl+C or `app.stop_server()`. A hard kill (e.g. Task Manager, `terminate()` on Windows) sends no last backup; then the last periodic one is used.

| Endpoint | Body |
|---|---|
| `/admin/status` | `password` |
| `/admin/trusted/list` | `password` |
| `/admin/trusted/add` | `password`, `url` |
| `/admin/trusted/remove` | `password`, `url` |
| `/admin/trusted/connect` | `password`, `url` (start the handshake again) |
| `/admin/clients` | `password` (all clients of this server with waiting message count) |
| `/admin/mailbox` | `password`, `client_ip` (what waits in the mailbox – nothing is taken out) |
| `/admin/settings` | `password`, optional `relay_mode`, `accept_relayed`, `backup_mode`, `agent_mode`, `conversation_mode`, `routing`, `friends_mode` |
| `/admin/blocked/add` · `/admin/blocked/remove` · `/admin/blocked/list` | `password`, `url` (BridgeFriends block list) |
| `/admin/friends` | `password` (friendships, invitations, friend connections, blocked servers) |
| `/admin/routes` | `password` (lines, tables of the partners, best ways) |
| `/admin/analysis` | `password` (counters, timings, mailboxes, lines, conversations, errors) |
| `/admin/agent` | `password`, optional `action`: `status` (default) · `reset` · `export` |
| `/admin/backup/status` | `password` |
| `/admin/backup/now` | `password` (send a backup right now) |
| `/admin/backup/restore` | `password` (replace everything in RAM with the newest backup) |
| `/admin/reset` | `password` (removes clients, messages, realms; keeps trusted servers) |
| `/admin/password/change` | `password`, `new_password` |

Use https in production. The handshake secret and all tokens travel over the connection.

## Tests

```
python tests/e2e_two_servers.py
python tests/e2e_features.py
python tests/e2e_realm_sync.py
python tests/e2e_express.py
python tests/e2e_agent.py
python tests/e2e_messaging.py
python tests/e2e_routing.py
python tests/e2e_hardening.py
python tests/e2e_friends.py
python tests/e2e_bugfixes.py
python tests/e2e_roblox.py
python extensions/roblox/tests/run_tests.py   # needs Lune 0.8.9, see extensions/roblox/README.md
python extensions/java/run_tests.py           # needs a JDK 21+ (javac)
```

The first test starts two real servers and checks messages, realms, commands, trust, restart and brute force.
The second one starts three servers (A–B–C) and checks the following:

- long polling
- stable identity
- direct message settings
- message status
- command catalog, calls with waiting and host choice
- topics across servers
- progress of long tasks (off / latest / all)
- relaying A → B → C
- backup and restore after a normal shutdown and after a crash

`e2e_realm_sync.py` checks the copies of realms on member servers (push, regular sync, stale, kick across servers),
`e2e_express.py` signatures, argument/response checks and `/express/schema`, `e2e_agent.py` the BridgeAgent
(learning, estimates, task status, strategy fastest, reliability, modes, backup).

`e2e_messaging.py` checks the modes compressed and temporary, times with timezones, planned messages, broadcast and
conversations across servers. `e2e_routing.py` starts three servers and breaks or slows down lines (file
`tests/routing_faults.json`) to check the best way and the failover. `e2e_hardening.py` checks bad inputs (NaN,
broken unicode, huge bodies), limits, planned messages over a restart and a backup that is too big.
`e2e_bugfixes.py` checks the fixes of the bug hunt of 01.11.2026 (nesting, number overflow, budgets, login and admin
locks, codes, roles, BridgeExpress budget, BridgeFriends during a restore, fake hello, big backup).
`e2e_roblox.py` checks what the Roblox extension needs: batch poll (`max_messages`), `include_self`, `/client/delete`,
publish inside a poll (`publish`) and the limits in `/server/status`.
`e2e_friends.py` starts A ↔ B (trusted) and C (neutral) and checks friendships with name / code + password, wrong
passwords and guessing, manual accept, friend messages in all modes, faked tokens and connections, status (presence,
idle, slow line, waiting messages), the block list, `friends_mode`, removing and a restart with backup.

### Härtetest (Angriffe von außen)

`Bridge_Tester/attack/attack_app.py` ist ein eigenes Programm, das echte Server startet und sie nur über HTTP
anzugreifen versucht: kaputte Eingaben, fremde Daten lesen, sich als anderer Client/Server ausgeben, den Server
überlasten, unerlaubte Server-zu-Server-Aufrufe, SSRF und die Pull-only-Regel. Jeder Angriff endet mit
`HÄLT` oder `KAPUTT`; Rückgabecode 0 = alles HÄLT.

```
python attack/attack_app.py      # aus dem Ordner Bridge_Tester
```

### Härtung am 01.11.2026 (nach einer zweiten Prüfung der Bugfixes)

Die Fehlersuche hatte ein paar neue Probleme eingeführt; sie sind behoben:

- **Login:** Der Zähler pro Absender-Adresse (viele Clients teilen sich oft eine IP, z. B. hinter NAT) wird bei
  jedem erfolgreichen Login geleert. Vorher konnte eine Adresse durch falsche Logins anderer Konten gesperrt werden,
  sodass auch ein richtiges Passwort abgewiesen wurde. Grenze: `max_failed_attempts × login_host_attempt_multiplier`.
- **Sessions pro Client** sind jetzt über `protocol.max_sessions_per_client` einstellbar.
- **Realms:** Der Zähler gegen das Raten von Zugangsschlüsseln/Codes wird nur zurückgesetzt, wenn wirklich ein
  Geheimnis geprüft wurde - der Beitritt zu einem öffentlichen Realm (oder ein erneuter Beitritt als Mitglied) setzt
  ihn nicht mehr zurück.
- **BridgeFriends:** Eine neu angelegte Tür mit gleichem Namen startet ohne alte Sperre; die Sperrliste merkt sich
  nicht unbegrenzt viele Einträge. Blockieren/Entsperren und die Vertrauensprüfung vergleichen Server nach Host und
  Port (jede Schreibweise derselben URL zählt gleich); ein wirklich vertrauter, verbundener Server gewinnt gegen einen
  versehentlichen Eintrag in der Sperrliste.
- **BridgeExpress:** Eine Signatur, deren Typ nach der Normalisierung über 500 Zeichen wächst, wird schon beim
  Anlegen abgelehnt - sonst hätte ein anderer Server sie verworfen und die strenge Prüfung dort still übersprungen.
