import base64
import os
import time
from typing import Dict

from eth_account.messages import encode_defunct
from web3 import Web3

TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000


class GarminAuthError(Exception):
    """Base exception for Garmin authentication errors."""


class MissingHeadersError(GarminAuthError):
    """Raised when required headers are missing."""


class InvalidTimestampError(GarminAuthError):
    """Raised when timestamp is too old or too far in future."""


class InvalidSignatureError(GarminAuthError):
    """Raised when signature verification fails."""


class InvalidMessageError(GarminAuthError):
    """Raised when message format is invalid."""


def _tolerance_ms() -> int:
    raw = os.getenv("AUTH_TIMESTAMP_TOLERANCE_MS", "").strip()
    if not raw:
        return TIMESTAMP_TOLERANCE_MS
    try:
        return max(1, int(raw))
    except ValueError:
        return TIMESTAMP_TOLERANCE_MS


def _normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _decode_message(encoded_message: str) -> str:
    raw = encoded_message.strip()
    padding = "=" * (-len(raw) % 4)
    try:
        decoded = base64.b64decode(raw + padding)
    except Exception as exc:
        raise InvalidMessageError(f"Failed to decode base64 message: {exc}")
    try:
        return decoded.decode("utf-8")
    except Exception as exc:
        raise InvalidMessageError(f"Failed to decode message bytes: {exc}")


def verify_garmin_auth(headers: Dict[str, str], expected_path: str) -> Dict[str, str]:
    """
    Verifies wallet signature and extracts authenticated address + profile ID.
    """
    normalized = _normalize_headers(headers)
    address = normalized.get("x-medoxie-address")
    profile_id = normalized.get("x-medoxie-profile-id")
    timestamp = normalized.get("x-medoxie-timestamp")
    encoded_message = normalized.get("x-medoxie-message")
    signature = normalized.get("x-medoxie-signature")

    if not all([address, profile_id, timestamp, encoded_message, signature]):
        missing = [k for k, v in [
            ("x-medoxie-address", address),
            ("x-medoxie-profile-id", profile_id),
            ("x-medoxie-timestamp", timestamp),
            ("x-medoxie-message", encoded_message),
            ("x-medoxie-signature", signature),
        ] if not v]
        raise MissingHeadersError(f"Missing required authentication headers: {', '.join(missing)}")

    address = address.lower()
    profile_id = profile_id.lower()

    message = _decode_message(encoded_message)

    try:
        timestamp_ms = int(timestamp)
    except ValueError:
        raise InvalidTimestampError(f"Invalid timestamp format: {timestamp}")

    now_ms = int(time.time() * 1000)
    age = abs(now_ms - timestamp_ms)
    tolerance = _tolerance_ms()
    if age > tolerance:
        raise InvalidTimestampError(
            f"Request timestamp too old or too far in future: {age}ms (max: {tolerance}ms)"
        )

    expected_message = (
        "Medoxie Garmin API Access\n"
        f"address: {address}\n"
        f"profileId: {profile_id}\n"
        f"timestamp: {timestamp}\n"
        f"path: {expected_path}"
    )
    if message != expected_message:
        raise InvalidMessageError(
            "Message does not match expected path or profile ID."
        )

    try:
        message_hash = encode_defunct(text=message)
        w3 = Web3()
        recovered_address = w3.eth.account.recover_message(message_hash, signature=signature)
    except Exception as exc:
        raise InvalidSignatureError(f"Invalid signature format: {exc}")

    if recovered_address.lower() != address:
        raise InvalidSignatureError(
            f"Signature does not match claimed address. Recovered: {recovered_address}"
        )

    return {
        "address": address,
        "profileId": profile_id,
        "timestamp": timestamp_ms,
        "path": expected_path,
    }
