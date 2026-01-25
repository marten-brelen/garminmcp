import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from eth_account import Account
from eth_account.messages import encode_defunct

from .token_store import consume_nonce


def _allowed_origins() -> set[str]:
    raw = os.getenv("AUTH_ALLOWED_ORIGINS", "").strip()
    if not raw:
        return set()
    return {o.strip() for o in raw.split(",") if o.strip()}


def _max_age_seconds() -> int:
    raw = os.getenv("AUTH_MAX_AGE_SECONDS", "120")
    try:
        return max(1, int(raw))
    except ValueError:
        return 120


def _parse_message_fields(message: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for line in message.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key:
            fields[key] = value
    required = ("address", "nonce", "issuedat", "origin")
    missing = [k for k in required if not fields.get(k)]
    if missing:
        raise ValueError(f"missing_fields:{','.join(missing)}")
    return fields


def _parse_issued_at(raw: str) -> datetime:
    value = raw.strip()
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


async def verify_wallet_headers(
    address: str,
    message: str,
    signature: str,
) -> Tuple[bool, str]:
    # Keep the raw header value for signature verification.
    raw_message = message
    # Allow clients to send literal "\n" in headers for parsing.
    parsed_message = message.replace("\\n", "\n")
    try:
        fields = _parse_message_fields(parsed_message)
    except ValueError as e:
        return False, str(e)

    msg_address = fields["address"].lower()
    header_address = address.lower()
    if msg_address != header_address:
        return False, "address_mismatch"

    try:
        recovered = Account.recover_message(encode_defunct(text=raw_message), signature=signature)
    except Exception:
        return False, "bad_signature"
    if recovered.lower() != header_address:
        return False, "signature_mismatch"

    try:
        issued_at = _parse_issued_at(fields["issuedat"])
    except Exception:
        return False, "invalid_issued_at"

    now = datetime.now(timezone.utc)
    if issued_at > now + timedelta(seconds=30):
        return False, "issued_at_in_future"
    if now - issued_at > timedelta(seconds=_max_age_seconds()):
        return False, "issued_at_expired"

    allowed = _allowed_origins()
    if allowed and fields["origin"] not in allowed:
        return False, "origin_not_allowed"

    if not await consume_nonce(header_address, fields["nonce"]):
        return False, "nonce_invalid"

    return True, "ok"
