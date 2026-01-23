## Garmin REST API

Simple FastAPI server that wraps `python-garminconnect` and exposes REST endpoints for Garmin auth and data.

### Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Run locally:
```bash
uvicorn api.index:app --reload
```

### Environment variables

- `CORS_ALLOW_ORIGINS` (comma-separated). Example: `http://localhost:3000,https://medoxie.com`
- `REQUIRE_HTTPS` (default `1`). Set `0` to allow http for local dev.
- `AUTH_PENDING_TTL_SECONDS` (default `300`) MFA pending credentials TTL.
- `AUTH_NONCE_TTL_SECONDS` (default `300`) Nonce TTL.
- `TOKEN_STORE_DIR` (optional). Directory for file-based token storage.
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` or `KV_REST_API_URL`, `KV_REST_API_TOKEN`

### REST endpoints

#### POST `/auth/start`
Body:
```json
{ "email": "user@example.com", "password": "secret", "user_id": "user-123" }
```

Response:
- `{ "status": "ok" }` on success
- `{ "status": "needs_mfa", "mfa_token": "..." }` when MFA required

#### POST `/auth/finish`
Body:
```json
{ "user_id": "user-123", "mfa_code": "123456", "mfa_token": "..." }
```

Response:
```json
{ "status": "ok" }
```

#### GET `/sleep`
Query params:
- `user_id` (required)
- `date` (YYYY-MM-DD) or `startDate`/`endDate` (YYYY-MM-DD)

Example:
```bash
curl "http://localhost:8000/sleep?user_id=user-123&date=2024-01-01"
```

#### GET `/activities`
Query params:
- `user_id` (required)
- `limit` (optional, default 20)
- `startDate`/`endDate` (YYYY-MM-DD)

Example:
```bash
curl "http://localhost:8000/activities?user_id=user-123&limit=5"
```

### Optional nonce endpoint

GET `/auth/nonce?address=0x...` returns `{ "nonce": "..." }`. If Redis/KV is not configured, a temporary in-memory fallback is used.

### Deployment notes

Vercel can run this API, but if you need stable long-running behavior or file-based token storage, consider Render, Fly.io, or Railway.
