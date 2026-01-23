import os
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple

from garth.exc import GarthHTTPError
from garminconnect import Garmin, GarminConnectAuthenticationError, GarminConnectConnectionError

from .token_store import b64_to_dir, load_tokens, save_tokens, zip_dir_to_b64


class GarminAuthError(Exception):
    pass


_PENDING_CREDS: dict[str, tuple[str, str, float]] = {}


def _pending_ttl_seconds() -> int:
    raw = os.getenv("AUTH_PENDING_TTL_SECONDS", "300")
    try:
        return max(1, int(raw))
    except ValueError:
        return 300


def _set_pending_creds(user_id: str, email: str, password: str) -> None:
    _PENDING_CREDS[user_id] = (email, password, time.time() + _pending_ttl_seconds())


def _pop_pending_creds(user_id: str) -> Optional[tuple[str, str]]:
    entry = _PENDING_CREDS.get(user_id)
    if not entry:
        return None
    email, password, expires_at = entry
    if time.time() > expires_at:
        _PENDING_CREDS.pop(user_id, None)
        return None
    _PENDING_CREDS.pop(user_id, None)
    return email, password


def _mk_token_dir(user_id: str) -> str:
    d = tempfile.mkdtemp(prefix=f"garmin_tokens_{user_id}_")
    Path(d).mkdir(parents=True, exist_ok=True)
    return d


async def get_logged_in_client(
    user_id: str,
    email: Optional[str] = None,
    password: Optional[str] = None,
) -> Tuple[Garmin, str]:
    """
    Returns (client, token_dir).
    Tries stored tokens first. If missing/invalid, uses email+password login.
    """
    token_dir = _mk_token_dir(user_id)

    # Restore tokens if present
    existing = await load_tokens(user_id)
    if existing:
        b64_to_dir(existing, token_dir)

    # 1) Try token login
    try:
        g = Garmin()
        g.login(token_dir)  # tokenstore path
        return g, token_dir
    except Exception:
        pass

    # 2) Need creds to login
    if not email or not password:
        raise GarminAuthError("No valid stored tokens and no email/password provided.")

    try:
        g = Garmin(email=email, password=password, is_cn=False, return_on_mfa=True)
        result = g.login()
        # garminconnect example returns (result1, result2) when return_on_mfa=True
        if isinstance(result, tuple) and len(result) == 2 and result[0] == "needs_mfa":
            # caller must resume_login with MFA code
            raise GarminAuthError(f"MFA_REQUIRED::{result[1]}")
        # If login succeeded, persist tokens
        g.garth.dump(token_dir)
        await save_tokens(user_id, zip_dir_to_b64(token_dir))
        return g, token_dir
    except GarminConnectAuthenticationError as e:
        raise GarminAuthError(f"AUTH_FAILED::{e}")
    except GarminConnectConnectionError as e:
        raise GarminAuthError(f"CONNECTION_FAILED::{e}")
    except GarthHTTPError as e:
        raise GarminAuthError(f"GARTH_HTTP_ERROR::{e}")
    except Exception as e:
        raise GarminAuthError(f"UNKNOWN::{e}")


async def start_login(user_id: str, email: str, password: str) -> dict:
    """
    Attempts login. Returns status and MFA context if needed.
    """
    try:
        g = Garmin(email=email, password=password, is_cn=False, return_on_mfa=True)
        result = g.login()
        if isinstance(result, tuple) and len(result) == 2 and result[0] == "needs_mfa":
            _set_pending_creds(user_id, email, password)
            return {"status": "needs_mfa", "mfa_token": result[1]}
        token_dir = _mk_token_dir(user_id)
        g.garth.dump(token_dir)
        await save_tokens(user_id, zip_dir_to_b64(token_dir))
        return {"status": "ok"}
    except GarminConnectAuthenticationError as e:
        raise GarminAuthError(f"AUTH_FAILED::{e}")
    except GarminConnectConnectionError as e:
        raise GarminAuthError(f"CONNECTION_FAILED::{e}")
    except GarthHTTPError as e:
        raise GarminAuthError(f"GARTH_HTTP_ERROR::{e}")
    except Exception as e:
        raise GarminAuthError(f"UNKNOWN::{e}")


async def resume_mfa_login(
    user_id: str,
    mfa_token: str,
    mfa_code: str,
    email: Optional[str] = None,
    password: Optional[str] = None,
) -> None:
    """
    Completes MFA flow and stores tokens.
    """
    if not email or not password:
        pending = _pop_pending_creds(user_id)
        if not pending:
            raise GarminAuthError("MFA_PENDING_EXPIRED")
        email, password = pending
    token_dir = _mk_token_dir(user_id)
    g = Garmin(email=email, password=password, is_cn=False, return_on_mfa=True)
    g.resume_login(mfa_token, mfa_code)
    g.garth.dump(token_dir)
    await save_tokens(user_id, zip_dir_to_b64(token_dir))