"""
main.py
───────
Command-line interface for ThreatIntel Aggregator.

Usage
─────
    python main.py <indicator>
    python main.py --bulk indicators.txt

Examples
────────
    python main.py 8.8.8.8
    python main.py evil.example.com
    python main.py 44d88612fea8a8f36de82e1278abb02f
    python main.py --bulk iocs.txt
"""

import argparse
import sys
import logging
from typing import Any

from config import VIRUSTOTAL_API_KEY, OTX_API_KEY
from validators import validate_indicator
from database import init_db, get_cached, save_lookup
from scoring import compute_score
import vt_client
import otx_client

logger = logging.getLogger(__name__)

# ANSI colour codes (disabled on Windows if not supported).
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

_VERDICT_COLOUR = {
    "Low":    _GREEN,
    "Medium": _YELLOW,
    "High":   _RED,
}


def _colour(text: str, code: str) -> str:
    """Wrap *text* in ANSI colour codes when stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


def _lookup(indicator: str) -> dict[str, Any]:
    """
    Perform a full IoC lookup: validate → cache check → API calls → score → save.

    Returns a result dict suitable for display.
    """
    try:
        normalised, ioc_type = validate_indicator(indicator)
    except ValueError as exc:
        return {"error": str(exc), "indicator": indicator}

    # ── Cache check ───────────────────────────────────────────────────────────
    cached = get_cached(normalised)
    if cached:
        cached["from_cache"] = True
        return cached

    # ── API lookups ───────────────────────────────────────────────────────────
    logger.info("Starting lookup for %s (%s)", normalised, ioc_type)

    dispatch = {
        "ipv4":   (vt_client.lookup_ip,     otx_client.lookup_ip),
        "domain": (vt_client.lookup_domain, otx_client.lookup_domain),
        "md5":    (vt_client.lookup_hash,   otx_client.lookup_hash),
        "sha1":   (vt_client.lookup_hash,   otx_client.lookup_hash),
        "sha256": (vt_client.lookup_hash,   otx_client.lookup_hash),
    }
    vt_fn, otx_fn = dispatch[ioc_type]

    vt_result  = vt_fn(normalised)
    otx_result = otx_fn(normalised)

    # ── Scoring ───────────────────────────────────────────────────────────────
    score, verdict = compute_score(vt_result, otx_result)

    # ── Persist ───────────────────────────────────────────────────────────────
    save_lookup(normalised, ioc_type, vt_result, otx_result, score, verdict)

    return {
        "indicator":   normalised,
        "ioc_type":    ioc_type,
        "vt_result":   vt_result,
        "otx_result":  otx_result,
        "score":       score,
        "verdict":     verdict,
        "from_cache":  False,
    }


def _print_result(result: dict[str, Any]) -> None:
    """Print a human-readable lookup result to stdout."""
    if "error" in result:
        print(_colour(f"✗ Error: {result['error']}", _RED))
        return

    indicator = result["indicator"]
    ioc_type  = result["ioc_type"]
    score     = result["score"]
    verdict   = result["verdict"]
    from_cache = result.get("from_cache", False)
    vt         = result.get("vt_result") or {}
    otx        = result.get("otx_result") or {}

    colour = _VERDICT_COLOUR.get(verdict, _RESET)
    cache_note = " (cached)" if from_cache else ""

    print()
    print(_colour(f"  IoC       : {indicator} [{ioc_type}]", _CYAN))
    print(f"  Score     : {score:.1f} / 100{cache_note}")
    print(f"  Verdict   : {_colour(verdict, colour + _BOLD)}")
    print()

    # VirusTotal breakdown
    if "error" in vt:
        print(f"  VirusTotal: {_colour('error – ' + vt['error'], _YELLOW)}")
    elif vt:
        print(
            f"  VirusTotal: {vt.get('malicious', 0)} malicious, "
            f"{vt.get('suspicious', 0)} suspicious "
            f"(out of {vt.get('total', 0)} engines)"
        )
    else:
        print(f"  VirusTotal: {_colour('no data', _YELLOW)}")

    # OTX breakdown
    if "error" in otx:
        print(f"  OTX       : {_colour('error – ' + otx['error'], _YELLOW)}")
    elif otx:
        families = otx.get("malware_families", [])
        fam_str  = ", ".join(families[:5]) if families else "none identified"
        print(
            f"  OTX       : {otx.get('pulse_count', 0)} pulse(s) – "
            f"malware families: {fam_str}"
        )
    else:
        print(f"  OTX       : {_colour('no data', _YELLOW)}")

    print()


def _check_keys() -> None:
    """Warn if API keys are not configured."""
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY is not set in .env – VT lookups will fail.")
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY is not set in .env – OTX lookups will fail.")


def _run_bulk(path: str) -> None:
    """Read IoCs line by line from *path* and look up each one."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError as exc:
        print(_colour(f"Cannot open file '{path}': {exc}", _RED))
        sys.exit(1)

    if not lines:
        print(_colour("File is empty – nothing to look up.", _YELLOW))
        return

    print(f"\nBulk lookup: {len(lines)} indicator(s) from '{path}'\n")
    for idx, line in enumerate(lines, start=1):
        print(_colour(f"[{idx}/{len(lines)}] {line}", _CYAN))
        result = _lookup(line)
        _print_result(result)


def main() -> None:
    """Entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="threatintel",
        description="ThreatIntel Aggregator – check an IoC against VirusTotal and OTX.",
    )
    parser.add_argument(
        "indicator",
        nargs="?",
        help="IP address, domain, or file hash to look up.",
    )
    parser.add_argument(
        "--bulk",
        metavar="FILE",
        help="Path to a .txt file with one IoC per line.",
    )
    args = parser.parse_args()

    init_db()
    _check_keys()

    if args.bulk:
        _run_bulk(args.bulk)
    elif args.indicator:
        result = _lookup(args.indicator)
        _print_result(result)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
