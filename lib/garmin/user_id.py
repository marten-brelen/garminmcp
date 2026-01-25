import json
import os
from typing import Optional

import requests

LENS_API_URL = os.getenv("LENS_API_URL", "https://api.lens.xyz")


def _get_profile_data(profile_id: str) -> Optional[dict]:
    try:
        response = requests.get(
            f"{LENS_API_URL}/account",
            params={"address": profile_id},
            timeout=10,
        )
    except Exception:
        return None
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except Exception:
        return None


def _extract_email_from_metadata(metadata: dict) -> Optional[str]:
    attributes = metadata.get("attributes", [])
    for attr in attributes:
        key = str(attr.get("key", "")).lower()
        if key in ["garminconnect", "garmin", "email", "emailaddress"]:
            value = attr.get("value")
            if not value:
                continue
            if isinstance(value, str) and value.strip().startswith("{"):
                try:
                    parsed = json.loads(value)
                    return parsed.get("email") or parsed.get("emailAddress")
                except Exception:
                    return value
            return value
    return None


def resolve_user_id_from_profile(profile_id: str) -> Optional[str]:
    """
    Resolves the user's Garmin email from their Lens profile metadata.
    """
    data = _get_profile_data(profile_id)
    if not data:
        return None
    metadata = data.get("metadata") or data.get("account", {}).get("metadata") or {}
    return _extract_email_from_metadata(metadata)
