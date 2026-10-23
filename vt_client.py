"""
vt_client.py
────────────
VirusTotal API v3 client.

Endpoints used
──────────────
- GET /ip_addresses/{ip}
- GET /domains/{domain}
- GET /files/{hash}

Rate limiting
─────────────
The free VirusTotal tier allows approximately 4 requests/minute.  This client
uses ``tenacity`` to retry on HTTP 429 (rate-limit) and transient 5xx errors
with exponential back-off, and enforces a minimum inter-request delay so the
caller does not need to think about timing.

Return shape
────────────
Each public function returns a dict with at least:
    {
        "malicious":   int,   # engines that flagged as malicious
        "suspicious":  int,   # engines that flagged as suspicious
        "harmless":    int,
        "undetected":  int,
        "total":       int,   # total engines that scanned
        "raw":         dict,  # full VirusTotal JSON response
    }
On failure (invalid key, 404, etc.) a dict with ``"error": "<message>"`` is
returned instead so callers can always pattern-match on the presence of
``"error"``.
"""

import logging
import time
from typing import Any

import requests
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

from config import (
    VIRUSTOTAL_API_KEY,
    VT_BASE_URL,
    VT_MAX_RETRIES,
    VT_TIMEOUT,
    VT_RATE_LIMIT_CALLS,
    VT_RATE_LIMIT_PERIOD,
)

logger = logging.getLogger(__name__)

# Minimum seconds to wait between VirusTotal requests (free tier pacing).
_MIN_INTERVAL: float = VT_RATE_LIMIT_PERIOD / VT_RATE_LIMIT_CALLS
_last_request_time: float = 0.0


def _pace() -> None:
    """Sleep just long enough to stay within the free-tier rate limit."""
    global _last_request_time
    elapsed = time.monotonic() - _last_request_time
    if elapsed < _MIN_INTERVAL:
        sleep_for = _MIN_INTERVAL - elapsed
        logger.debug("VT rate-pacing: sleeping %.1fs", sleep_for)
        time.sleep(sleep_for)
    _last_request_time = time.monotonic()


class _RateLimitError(Exception):
    """Raised internally when VirusTotal returns HTTP 429."""


def _build_headers() -> dict[str, str]:
    return {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}


def _parse_stats(data: dict[str, Any]) -> dict[str, Any]:
    """
    Extract last_analysis_stats from a VirusTotal response object.

    Handles both the top-level ``data.attributes`` shape and returns a
    normalised dict.
    """
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total":      total,
        "raw":        data,
    }


@retry(
    retry=retry_if_exception_type(_RateLimitError),
    stop=stop_after_attempt(VT_MAX_RETRIES),
    wait=wait_exponential(multiplier=15, min=15, max=120),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=False,
)
def _get(url: str) -> dict[str, Any]:
    """
    Execute a GET request against the VirusTotal API with retry on 429.

    Returns the parsed JSON body on success.  Raises ``_RateLimitError`` on
    HTTP 429 so that ``tenacity`` can retry.  Returns an error dict for all
    other non-2xx responses.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY is not configured."}

    _pace()
    try:
        resp = requests.get(url, headers=_build_headers(), timeout=VT_TIMEOUT)
    except requests.Timeout:
        return {"error": f"Request to {url} timed out after {VT_TIMEOUT}s."}
    except requests.RequestException as exc:
        return {"error": str(exc)}

    if resp.status_code == 429:
        logger.warning("VirusTotal rate limit hit; will retry.")
        raise _RateLimitError("rate limited")

    if resp.status_code == 401:
        return {"error": "Invalid VirusTotal API key (HTTP 401)."}

    if resp.status_code == 404:
        return {"error": f"Indicator not found in VirusTotal (HTTP 404)."}

    if not resp.ok:
        return {"error": f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:200]}"}

    try:
        return resp.json()
    except ValueError:
        return {"error": "VirusTotal returned non-JSON response."}


# ── Public API ────────────────────────────────────────────────────────────────

def lookup_ip(ip: str) -> dict[str, Any]:
    """
    Query VirusTotal for an IPv4 address.

    Parameters
    ----------
    ip:
        Dotted-decimal IPv4 string.

    Returns
    -------
    dict
        Normalised result dict (see module docstring) or ``{"error": "…"}``.
    """
    logger.info("VT lookup: IP %s", ip)
    data = _get(f"{VT_BASE_URL}/ip_addresses/{ip}")
    if "error" in data:
        return data
    return _parse_stats(data)


def lookup_domain(domain: str) -> dict[str, Any]:
    """
    Query VirusTotal for a domain name.

    Parameters
    ----------
    domain:
        Lower-cased domain string (e.g. ``"evil.example.com"``).

    Returns
    -------
    dict
        Normalised result dict or ``{"error": "…"}``.
    """
    logger.info("VT lookup: domain %s", domain)
    data = _get(f"{VT_BASE_URL}/domains/{domain}")
    if "error" in data:
        return data
    return _parse_stats(data)


def lookup_hash(file_hash: str) -> dict[str, Any]:
    """
    Query VirusTotal for a file hash (MD5, SHA-1, or SHA-256).

    Parameters
    ----------
    file_hash:
        Lower-cased hex hash string.

    Returns
    -------
    dict
        Normalised result dict or ``{"error": "…"}``.
    """
    logger.info("VT lookup: hash %s", file_hash)
    data = _get(f"{VT_BASE_URL}/files/{file_hash}")
    if "error" in data:
        return data
    return _parse_stats(data)
