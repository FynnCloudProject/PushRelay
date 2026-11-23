# FynnCloud PushRelay

Stateless APNs (and FCM) relay for self-hosted FynnCloud servers.

Self-hosted instances cannot bundle Apple APNs `.p8` signing keys, so they POST encrypted notification payloads and File Provider wakeup signals here and this service forwards them to Apple. Nothing is persisted to disk; all rate limits and metrics live in memory.

## Endpoints

| Method | Path | Auth | Notes |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | — | Enabled transports and version |
| `GET` | `/v1/info` | — | Protocol version, batch and byte limits |
| `POST` | `/v1/push` | Optional `RELAY_SHARED_SECRET` | Single push (`apns`, `apns-voip`, `apns-fileprovider`) |
| `POST` | `/v1/push/batch` | Optional `RELAY_SHARED_SECRET` | `{ "messages": [...] }`, up to `RELAY_MAX_BATCH_SIZE` |
| `GET` | `/metrics` | `METRICS_BEARER_TOKEN` or `ADMIN_PASSWORD` | Prometheus text exposition (`404` if neither is set) |
| `GET` | `/admin` | `ADMIN_PASSWORD` | In-memory metrics UI (`404` unless set) |
| `GET` | `/admin/metrics` | Session cookie or `ADMIN_PASSWORD` | Prometheus text exposition |
| `GET` | `/admin/metrics.json` | Session cookie or `ADMIN_PASSWORD` | JSON metrics snapshot |

### `POST /v1/push`

HPKE-encrypted alert, background, or VoIP push:

```json
{
  "transport": "apns-voip",
  "environment": "production",
  "target": "ch.fynncloud.talk.voip",
  "token": "<hex-device-token>",
  "kind": "voip",
  "urgency": "call",
  "ttlSeconds": 45,
  "keyId": "a3f91b02",
  "ciphertext": "<base64-hpke-ciphertext>"
}
```

File Provider wakeup (`apns-push-type: fileprovider`, `apns-priority: 5`):

```json
{
  "transport": "apns-fileprovider",
  "environment": "production",
  "target": "ch.fynncloud.app.pushkit.fileprovider",
  "token": "<hex-fileprovider-token>",
  "kind": "fileprovider",
  "ttlSeconds": 3600,
  "containerIdentifier": "NSFileProviderWorkingSetContainerItemIdentifier",
  "domain": "ch.fynncloud.app.FynnCloudFileProvider.<accountId>"
}
```

Responses return `{ "delivered", "unregistered", "apnsId", "reason" }`. A `410` (`"unregistered": true`) means Apple rejected the token (`Unregistered`, `BadDeviceToken`, `DeviceTokenNotForTopic`, `ExpiredToken`) and the caller should delete it; `502`/`503` are upstream or credential errors and should not prune the token.

## Configuration

See [`.env.example`](.env.example).

| Variable | Required | Default | Notes |
| :--- | :--- | :--- | :--- |
| `APNS_TEAM_ID` | Yes | — | Apple Developer Team ID |
| `APNS_KEY_ID` | Yes | — | APNs `.p8` Key ID |
| `APNS_PRIVATE_KEY_PATH` | One of 3 | — | Path to `.p8` file (or use `APNS_PRIVATE_KEY` / `APNS_PRIVATE_KEY_BASE64`) |
| `APNS_ALLOWED_TOPICS` | At least one topic | — | Comma-separated bundle IDs for alert/background pushes |
| `APNS_ALLOWED_VOIP_TOPICS` | At least one topic | — | Comma-separated `*.voip` topics |
| `APNS_ALLOWED_FILEPROVIDER_TOPICS` | At least one topic | — | Comma-separated `*.pushkit.fileprovider` topics |
| `APNS_ALLOW_SANDBOX` | No | `true` | Allow `environment: "sandbox"` dispatches |
| `RELAY_SHARED_SECRET` | No | — | Require `Authorization: Bearer <secret>` on `/v1/push*` |
| `TRUST_PROXY_HEADERS` | No | `false` | Trust `X-Forwarded-For` / `X-Real-IP` for IP rate limits |
| `RATE_LIMIT_IP_PER_MINUTE` | No | `600` | Per-IP request budget (`0` disables) |
| `RATE_LIMIT_TOKEN_PER_MINUTE` | No | `120` | Per-device-token budget (`0` disables) |
| `RELAY_MAX_BATCH_SIZE` | No | `100` | Max items per `/v1/push/batch` (`1`–`500`) |
| `ADMIN_PASSWORD` | No | — | Enables `/admin` UI (min 12 chars); also authorizes `/metrics` |
| `ADMIN_COOKIE_SECURE` | No | `true` | Set `false` only for local HTTP dev |
| `METRICS_BEARER_TOKEN` | No | — | Dedicated Bearer token for `GET /metrics` |

## Running

With Docker:

```bash
cp .env.example .env
# mount your AuthKey.p8 as ./AuthKey.p8 and fill in .env
docker compose up -d
```

Locally:

```bash
swift test
swift run PushRelay serve --hostname 0.0.0.0 --port 8080
```
