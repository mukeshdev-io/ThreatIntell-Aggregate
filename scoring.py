"""
scoring.py
──────────
Risk scoring: normalises raw VirusTotal and AlienVault OTX results into a
single 0-100 score and maps that score to a human-readable verdict.

Formula
───────
The combined score is a weighted average of two sub-scores:

    combined = 0.65 × vt_score + 0.35 × otx_score

VirusTotal sub-score (0-100)
    ratio = (malicious + 0.5 × suspicious) / total_engines
    vt_score = min(ratio × 100, 100)

    Weights:
        - malicious detections count fully (weight 1.0).
        - suspicious detections count at half weight (0.5) because they
          represent ambiguous signals.
        - harmless / undetected engines do NOT reduce the score (we avoid
          false negatives by only counting signals, not absences).
    
    If VirusTotal data is unavailable the sub-score defaults to 0 and the
    overall weight shifts entirely to OTX.

AlienVault OTX sub-score (0-100)
    Pulse count is mapped non-linearly using a logistic-inspired cap so that
    a single obscure pulse does not immediately drive the score to 100:

        pulse_buckets:
            0 pulses  →   0
            1         →  20
            2-4       →  40
            5-9       →  60
            10-24     →  80
            ≥ 25      → 100

    If OTX data is unavailable the sub-score defaults to 0 and the weight
    shifts entirely to VirusTotal.

Verdict thresholds
    Low    :  0 – 30
    Medium : 31 – 70
    High   : 71 – 100

When BOTH sources are unavailable the score is 0 and the verdict is "Low"
with a note that no data was available.
"""

import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)

# Type alias for the three verdict strings.
Verdict = Literal["Low", "Medium", "High"]

# Weight given to VirusTotal vs OTX in the combined score.
_VT_WEIGHT: float = 0.65
_OTX_WEIGHT: float = 0.35

# OTX pulse → sub-score bucket mapping (ascending pulse thresholds).
_OTX_BUCKETS: list[tuple[int, float]] = [
    (0,   0.0),
    (1,  20.0),
    (2,  40.0),
    (5,  60.0),
    (10, 80.0),
    (25, 100.0),
]


def _vt_sub_score(vt_result: dict[str, Any] | None) -> tuple[float, bool]:
    """
    Compute the VirusTotal sub-score (0-100).

    Returns
    -------
    (score, available)
        *available* is ``False`` when VT data was missing or contained an error.
    """
    if not vt_result or "error" in vt_result:
        return 0.0, False

    total: int = vt_result.get("total", 0)
    if total == 0:
        # No engines scanned — treat as unavailable to avoid division by zero.
        return 0.0, False

    malicious: int  = vt_result.get("malicious", 0)
    suspicious: int = vt_result.get("suspicious", 0)

    # Weighted hit count: malicious counts fully; suspicious at half.
    weighted_hits = malicious + 0.5 * suspicious
    ratio = weighted_hits / total
    score = min(ratio * 100.0, 100.0)

    logger.debug(
        "VT sub-score: malicious=%d suspicious=%d total=%d → %.1f",
        malicious, suspicious, total, score,
    )
    return score, True


def _otx_sub_score(otx_result: dict[str, Any] | None) -> tuple[float, bool]:
    """
    Compute the AlienVault OTX sub-score (0-100).

    Returns
    -------
    (score, available)
        *available* is ``False`` when OTX data was missing or contained an error.
    """
    if not otx_result or "error" in otx_result:
        return 0.0, False

    pulse_count: int = otx_result.get("pulse_count", 0)

    # Walk the bucket list and take the highest threshold that the pulse count
    # meets or exceeds.
    score = 0.0
    for threshold, bucket_score in _OTX_BUCKETS:
        if pulse_count >= threshold:
            score = bucket_score

    logger.debug("OTX sub-score: pulses=%d → %.1f", pulse_count, score)
    return score, True


def compute_score(
    vt_result: dict[str, Any] | None,
    otx_result: dict[str, Any] | None,
) -> tuple[float, Verdict]:
    """
    Combine VirusTotal and OTX results into a 0-100 risk score and verdict.

    Parameters
    ----------
    vt_result:
        Normalised VirusTotal result dict (as returned by ``vt_client``), or
        ``None`` / a dict containing ``"error"`` if the lookup failed.
    otx_result:
        Normalised OTX result dict (as returned by ``otx_client``), or ``None``
        / a dict containing ``"error"`` if the lookup failed.

    Returns
    -------
    (score, verdict)
        *score* is a float in [0, 100].
        *verdict* is one of ``"Low"``, ``"Medium"``, ``"High"``.
    """
    vt_score, vt_ok   = _vt_sub_score(vt_result)
    otx_score, otx_ok = _otx_sub_score(otx_result)

    if vt_ok and otx_ok:
        # Both sources available: weighted average.
        combined = _VT_WEIGHT * vt_score + _OTX_WEIGHT * otx_score
    elif vt_ok:
        # Only VT available: use VT score at full weight.
        combined = vt_score
    elif otx_ok:
        # Only OTX available: use OTX score at full weight.
        combined = otx_score
    else:
        # No data at all.
        combined = 0.0

    combined = round(min(max(combined, 0.0), 100.0), 1)
    verdict = score_to_verdict(combined)

    logger.info(
        "Score: vt=%.1f (ok=%s) otx=%.1f (ok=%s) → combined=%.1f (%s)",
        vt_score, vt_ok, otx_score, otx_ok, combined, verdict,
    )
    return combined, verdict


def score_to_verdict(score: float) -> Verdict:
    """
    Map a 0-100 numeric score to a ``Verdict`` string.

    Thresholds:
        0  – 30  → ``"Low"``
        31 – 70  → ``"Medium"``
        71 – 100 → ``"High"``
    """
    if score <= 30:
        return "Low"
    if score <= 70:
        return "Medium"
    return "High"
