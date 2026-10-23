"""
validators.py
─────────────
IoC type detection and validation using regular expressions.

Supported IoC types
───────────────────
- ipv4      – standard dotted-decimal IPv4 address
- domain    – hostname / domain (e.g. evil.com, sub.evil.com)
- md5       – 32 hex characters
- sha1      – 40 hex characters
- sha256    – 64 hex characters
"""

import re
from typing import Literal

# Type alias for the four recognised IoC categories.
IoCType = Literal["ipv4", "domain", "md5", "sha1", "sha256"]

# ── Compiled regex patterns ───────────────────────────────────────────────────

# IPv4: four 0-255 octets separated by dots.
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Domain: labels of 1-63 alnum/hyphen chars, at least one dot, TLD ≥ 2 chars.
# Allows subdomains; rejects bare hostnames (no dot) to keep FP rate low.
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}$"
)

# File hashes (hex strings of fixed length).
_MD5_RE    = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE   = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def detect_ioc_type(indicator: str) -> IoCType:
    """
    Detect the IoC type of *indicator* and return one of the ``IoCType`` literals.

    Parameters
    ----------
    indicator:
        The raw indicator string (will be stripped of leading/trailing whitespace).

    Returns
    -------
    IoCType
        One of ``"ipv4"``, ``"domain"``, ``"md5"``, ``"sha1"``, or ``"sha256"``.

    Raises
    ------
    ValueError
        If the indicator does not match any known IoC pattern.
    """
    value = indicator.strip()

    if _IPV4_RE.match(value):
        return "ipv4"
    if _SHA256_RE.match(value):
        return "sha256"
    if _SHA1_RE.match(value):
        return "sha1"
    if _MD5_RE.match(value):
        return "md5"
    if _DOMAIN_RE.match(value):
        return "domain"

    raise ValueError(
        f"Unrecognised indicator: '{value}'. "
        "Expected an IPv4 address, domain name, or MD5/SHA1/SHA256 hash."
    )


def validate_indicator(indicator: str) -> tuple[str, IoCType]:
    """
    Validate and normalise an indicator string.

    Returns a ``(normalised_value, ioc_type)`` tuple.  The normalised value is
    the stripped, lower-cased indicator (hashes are lower-cased; domains are
    lower-cased; IPs keep their original form).

    Raises
    ------
    ValueError
        If the indicator is empty or does not match any known IoC pattern.
    """
    if not indicator or not indicator.strip():
        raise ValueError("Indicator must not be empty.")

    stripped = indicator.strip()
    ioc_type = detect_ioc_type(stripped)

    # Normalise hashes and domains to lowercase; leave IPs unchanged.
    normalised = stripped if ioc_type == "ipv4" else stripped.lower()
    return normalised, ioc_type
