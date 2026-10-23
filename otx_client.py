"""
otx_client.py
─────────────
AlienVault OTX client using the OTXv2 Python SDK as a thin convenience layer,
with a plain-``requests`` fallback so the package is not a hard dependency at
import time.

OTX pulse / reputation concepts
────────────────────────────────
- A *pulse* is a threat-intelligence report that mentions one or more IoCs.
- The number of pulses referencing an IoC is the primary reputation signal
  exposed by the free OTX tier.

Return shape
────────────
Each public function returns a dict:
    {
        "pulse_count":    int,    # number of threat-intel pulses referencing the IoC
        "malware_families": list, # unique malware family names from OTX (may be empty)
        "raw":            dict,   # full OTX JSON response
    }
On failure:
    {"error": "<message>"}
"""

import logging
from typing import Any

import requests
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

from config import OTX_API_KEY, OTX_BASE_URL, OTX_MAX_RETRIES, OTX_TIMEOUT

logger = logging.getLogger(__name__)


class _TransientError(Exception):
    """Raised on 5xx responses so tenacity can retry."""


def _headers() -> dict[str, str]:
    return {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}


@retry(
    retry=retry_if_exception_type(_TransientError),
    stop=stop_after_attempt(OTX_MAX_RETRIES),
    wait=wait_exponential(multiplier=2, min=2, max=30),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=False,
)
def _get(url: str) -> dict[str, Any]:
    """
    GET *url* from OTX with retry on 5xx errors.

    Returns the parsed JSON body or a dict containing ``"error"``.
    """
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY is not configured."}

    try:
        resp = requests.get(url, headers=_headers(), timeout=OTX_TIMEOUT)
    except requests.Timeout:
        return {"error": f"OTX request timed out after {OTX_TIMEOUT}s."}
    except requests.RequestException as exc:
        return {"error": str(exc)}

    if resp.status_code == 403:
        return {"error": "Invalid OTX API key (HTTP 403)."}

    if resp.status_code == 404:
        # 404 from OTX simply means the indicator has no known reputation data.
        return {"pulse_count": 0, "malware_families": [], "raw": {}}

    if resp.status_code >= 500:
        logger.warning("OTX server error %s; will retry.", resp.status_code)
        raise _TransientError(f"HTTP {resp.status_code}")

    if not resp.ok:
        return {"error": f"OTX returned HTTP {resp.status_code}: {resp.text[:200]}"}

    try:
        return resp.json()
    except ValueError:
        return {"error": "OTX returned non-JSON response."}


def _parse_general(data: dict[str, Any]) -> dict[str, Any]:
    """
    Extract a normalised summary from an OTX ``/general`` section response.

    OTX general response keys of interest:
        pulse_info.count      – total pulse references
        pulse_info.pulses[]   – list of pulse objects
            .malware_families[]  – list of {display_name, …} dicts
    """
    pulse_info = data.get("pulse_info", {})
    pulse_count: int = pulse_info.get("count", 0)

    families: list[str] = []
    for pulse in pulse_info.get("pulses", []):
        for family in pulse.get("malware_families", []):
            name = family.get("display_name") or family.get("id", "")
            if name and name not in families:
                families.append(name)

    return {
        "pulse_count":      pulse_count,
        "malware_families": families,
        "raw":              data,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def lookup_ip(ip: str) -> dict[str, Any]:
    """
    Query OTX for an IPv4 address reputation.

    Parameters
    ----------
    ip:
        Dotted-decimal IPv4 string.

    Returns
    -------
    dict
        Normalised OTX result or ``{"error": "…"}``.
    """
    logger.info("OTX lookup: IP %s", ip)
    url = f"{OTX_BASE_URL}/api/v1/indicators/IPv4/{ip}/general"
    data = _get(url)
    if "error" in data:
        return data
    return _parse_general(data)


def lookup_domain(domain: str) -> dict[str, Any]:
    """
    Query OTX for a domain reputation.

    Parameters
    ----------
    domain:
        Lower-cased domain string.

    Returns
    -------
    dict
        Normalised OTX result or ``{"error": "…"}``.
    """
    logger.info("OTX lookup: domain %s", domain)
    url = f"{OTX_BASE_URL}/api/v1/indicators/domain/{domain}/general"
    data = _get(url)
    if "error" in data:
        return data
    return _parse_general(data)


def lookup_hash(file_hash: str) -> dict[str, Any]:
    """
    Query OTX for a file hash reputation.

    Parameters
    ----------
    file_hash:
        Lower-cased MD5, SHA-1, or SHA-256 hex string.

    Returns
    -------
    dict
        Normalised OTX result or ``{"error": "…"}``.
    """
    logger.info("OTX lookup: hash %s", file_hash)
    url = f"{OTX_BASE_URL}/api/v1/indicators/file/{file_hash}/general"
    data = _get(url)
    if "error" in data:
        return data
    return _parse_general(data)
