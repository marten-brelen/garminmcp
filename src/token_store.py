import base64
import io
import os
import secrets
import zipfile
from typing import Optional

from upstash_redis.asyncio import Redis


def _env_first(*names: str) -> Optional[str]:
    for n in names:
        v = os.getenv(n)
        if v:
            return v
    return None


def get_redis() -> Optional[Redis]:
    """
    Supports either:
      - Upstash native env vars: UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN
      - Vercel KV env vars:      KV_REST_API_URL / KV_REST_API_TOKEN
    """
    url = _env_first("UPSTASH_REDIS_REST_URL", "KV_REST_API_URL")
    token = _env_first("UPSTASH_REDIS_REST_TOKEN", "KV_REST_API_TOKEN")
    if not url or not token:
        return None
    return Redis(url=url, token=token)


def _nonce_ttl_seconds() -> int:
    raw = os.getenv("AUTH_NONCE_TTL_SECONDS", "300")
    try:
        return max(1, int(raw))
    except ValueError:
        return 300


async def issue_nonce(address: str) -> Optional[str]:
    r = get_redis()
    if not r:
        return None
    nonce = secrets.token_urlsafe(32)
    addr = address.lower()
    await r.set(f"auth:nonce:{addr}", nonce, ex=_nonce_ttl_seconds())
    return nonce


async def consume_nonce(address: str, nonce: str) -> bool:
    r = get_redis()
    if not r:
        return False
    addr = address.lower()
    key = f"auth:nonce:{addr}"
    existing = await r.get(key)
    if not existing or existing != nonce:
        return False
    await r.delete(key)
    return True


def zip_dir_to_b64(dir_path: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(dir_path):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, dir_path)
                z.write(full, rel)
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def b64_to_dir(b64: str, dir_path: str) -> None:
    raw = base64.b64decode(b64.encode("utf-8"))
    with zipfile.ZipFile(io.BytesIO(raw), "r") as z:
        z.extractall(dir_path)


async def load_tokens(user_id: str) -> Optional[str]:
    r = get_redis()
    if not r:
        return None
    return await r.get(f"garmin:tokens:{user_id}")


async def save_tokens(user_id: str, b64zip: str, ttl_seconds: int = 60 * 60 * 24 * 365) -> None:
    r = get_redis()
    if not r:
        return
    await r.set(f"garmin:tokens:{user_id}", b64zip, ex=ttl_seconds)