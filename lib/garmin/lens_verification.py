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


def verify_lens_profile_ownership(wallet_address: str, profile_id: str) -> bool:
    """
    Verifies that a Lens profile ID belongs to the given wallet address.
    """
    data = _get_profile_data(profile_id)
    if not data:
        return False
    profile_owner = (
        data.get("account", {}).get("address")
        or data.get("address")
        or data.get("ownedBy")
    )
    if not profile_owner:
        return False
    return profile_owner.lower() == wallet_address.lower()
