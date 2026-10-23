"""
tests/test_scoring.py
─────────────────────
Unit tests for scoring.py — normalisation, formula, and verdict mapping.

All tests use plain dicts that mimic the shapes returned by vt_client and
otx_client so no network calls are made.
"""

import pytest

from scoring import compute_score, score_to_verdict, _vt_sub_score, _otx_sub_score


# ── score_to_verdict ──────────────────────────────────────────────────────────

class TestScoreToVerdict:
    def test_zero_is_low(self):
        assert score_to_verdict(0) == "Low"

    def test_30_is_low(self):
        assert score_to_verdict(30) == "Low"

    def test_31_is_medium(self):
        assert score_to_verdict(31) == "Medium"

    def test_70_is_medium(self):
        assert score_to_verdict(70) == "Medium"

    def test_71_is_high(self):
        assert score_to_verdict(71) == "High"

    def test_100_is_high(self):
        assert score_to_verdict(100) == "High"


# ── _vt_sub_score ─────────────────────────────────────────────────────────────

class TestVTSubScore:
    def _make_vt(self, malicious: int, suspicious: int, total: int) -> dict:
        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   total - malicious - suspicious,
            "undetected": 0,
            "total":      total,
        }

    def test_no_detections(self):
        score, ok = _vt_sub_score(self._make_vt(0, 0, 70))
        assert ok is True
        assert score == 0.0

    def test_all_malicious(self):
        score, ok = _vt_sub_score(self._make_vt(70, 0, 70))
        assert ok is True
        assert score == 100.0

    def test_half_malicious(self):
        score, ok = _vt_sub_score(self._make_vt(35, 0, 70))
        assert ok is True
        assert pytest.approx(score, 0.1) == 50.0

    def test_suspicious_half_weight(self):
        # 10 suspicious out of 100 → (10 * 0.5) / 100 * 100 = 5.0
        score, ok = _vt_sub_score(self._make_vt(0, 10, 100))
        assert ok is True
        assert pytest.approx(score, 0.01) == 5.0

    def test_none_result_unavailable(self):
        score, ok = _vt_sub_score(None)
        assert ok is False
        assert score == 0.0

    def test_error_result_unavailable(self):
        score, ok = _vt_sub_score({"error": "API key invalid"})
        assert ok is False
        assert score == 0.0

    def test_zero_total_unavailable(self):
        score, ok = _vt_sub_score({"malicious": 0, "suspicious": 0, "total": 0})
        assert ok is False

    def test_score_capped_at_100(self):
        # Passing artificially high counts — result must not exceed 100.
        score, _ = _vt_sub_score(self._make_vt(200, 200, 200))
        assert score == 100.0


# ── _otx_sub_score ────────────────────────────────────────────────────────────

class TestOTXSubScore:
    def _make_otx(self, pulse_count: int) -> dict:
        return {"pulse_count": pulse_count, "malware_families": []}

    def test_zero_pulses(self):
        score, ok = _otx_sub_score(self._make_otx(0))
        assert ok is True
        assert score == 0.0

    def test_one_pulse(self):
        score, ok = _otx_sub_score(self._make_otx(1))
        assert ok is True
        assert score == 20.0

    def test_two_pulses(self):
        score, _ = _otx_sub_score(self._make_otx(2))
        assert score == 40.0

    def test_five_pulses(self):
        score, _ = _otx_sub_score(self._make_otx(5))
        assert score == 60.0

    def test_ten_pulses(self):
        score, _ = _otx_sub_score(self._make_otx(10))
        assert score == 80.0

    def test_25_pulses_max(self):
        score, _ = _otx_sub_score(self._make_otx(25))
        assert score == 100.0

    def test_large_pulse_count_capped(self):
        score, _ = _otx_sub_score(self._make_otx(1000))
        assert score == 100.0

    def test_none_result_unavailable(self):
        score, ok = _otx_sub_score(None)
        assert ok is False
        assert score == 0.0

    def test_error_result_unavailable(self):
        score, ok = _otx_sub_score({"error": "invalid key"})
        assert ok is False


# ── compute_score (integration) ───────────────────────────────────────────────

class TestComputeScore:
    def _vt(self, malicious: int, suspicious: int, total: int = 70) -> dict:
        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   total - malicious - suspicious,
            "undetected": 0,
            "total":      total,
        }

    def _otx(self, pulse_count: int) -> dict:
        return {"pulse_count": pulse_count, "malware_families": []}

    def test_both_clean_low(self):
        score, verdict = compute_score(self._vt(0, 0, 70), self._otx(0))
        assert verdict == "Low"
        assert score == 0.0

    def test_high_vt_high_score(self):
        # 70/70 malicious → vt_score=100; 0 OTX pulses → otx_score=0
        # combined = 0.65 * 100 + 0.35 * 0 = 65.0 → Medium
        score, verdict = compute_score(self._vt(70, 0, 70), self._otx(0))
        assert pytest.approx(score, 0.1) == 65.0
        assert verdict == "Medium"

    def test_both_high_verdict_high(self):
        # vt_score=100, otx_score=100 → combined=100
        score, verdict = compute_score(self._vt(70, 0, 70), self._otx(25))
        assert score == 100.0
        assert verdict == "High"

    def test_only_vt_available(self):
        # OTX error → weight falls entirely on VT
        score, verdict = compute_score(self._vt(70, 0, 70), {"error": "fail"})
        assert score == 100.0
        assert verdict == "High"

    def test_only_otx_available(self):
        # VT error → weight falls entirely on OTX
        # 10 pulses → otx_score = 80
        score, verdict = compute_score(None, self._otx(10))
        assert score == 80.0
        assert verdict == "High"

    def test_both_unavailable_low(self):
        score, verdict = compute_score(None, None)
        assert score == 0.0
        assert verdict == "Low"

    def test_score_bounded_0_to_100(self):
        score, _ = compute_score(self._vt(70, 70, 70), self._otx(1000))
        assert 0.0 <= score <= 100.0
