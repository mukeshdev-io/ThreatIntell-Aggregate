"""
tests/test_validators.py
────────────────────────
Unit tests for validators.py — IoC detection and validation.
"""

import pytest

from validators import validate_indicator, detect_ioc_type


# ── IPv4 ──────────────────────────────────────────────────────────────────────

class TestIPv4:
    def test_standard_ip(self):
        value, ioc_type = validate_indicator("8.8.8.8")
        assert value == "8.8.8.8"
        assert ioc_type == "ipv4"

    def test_leading_trailing_whitespace(self):
        value, ioc_type = validate_indicator("  1.2.3.4  ")
        assert value == "1.2.3.4"
        assert ioc_type == "ipv4"

    def test_max_octet_values(self):
        _, ioc_type = validate_indicator("255.255.255.255")
        assert ioc_type == "ipv4"

    def test_zero_octets(self):
        _, ioc_type = validate_indicator("0.0.0.0")
        assert ioc_type == "ipv4"

    def test_invalid_octet_256(self):
        with pytest.raises(ValueError):
            validate_indicator("256.1.1.1")

    def test_invalid_five_octets(self):
        with pytest.raises(ValueError):
            validate_indicator("1.2.3.4.5")

    def test_invalid_three_octets(self):
        with pytest.raises(ValueError):
            validate_indicator("1.2.3")


# ── Domain ────────────────────────────────────────────────────────────────────

class TestDomain:
    def test_simple_domain(self):
        value, ioc_type = validate_indicator("evil.com")
        assert value == "evil.com"
        assert ioc_type == "domain"

    def test_subdomain(self):
        _, ioc_type = validate_indicator("sub.evil.example.com")
        assert ioc_type == "domain"

    def test_domain_normalised_to_lowercase(self):
        value, _ = validate_indicator("EVIL.COM")
        assert value == "evil.com"

    def test_bare_hostname_no_dot_rejected(self):
        # A bare hostname with no dot (e.g. "localhost") should be rejected
        # because our regex requires at least one dot (for TLD).
        with pytest.raises(ValueError):
            validate_indicator("localhost")

    def test_invalid_domain_starts_with_hyphen(self):
        with pytest.raises(ValueError):
            validate_indicator("-badlabel.com")


# ── MD5 hash ──────────────────────────────────────────────────────────────────

class TestMD5:
    def test_valid_md5_lowercase(self):
        h = "44d88612fea8a8f36de82e1278abb02f"
        value, ioc_type = validate_indicator(h)
        assert ioc_type == "md5"
        assert value == h

    def test_valid_md5_uppercase_normalised(self):
        value, ioc_type = validate_indicator("44D88612FEA8A8F36DE82E1278ABB02F")
        assert ioc_type == "md5"
        assert value == "44d88612fea8a8f36de82e1278abb02f"

    def test_md5_wrong_length_rejected(self):
        with pytest.raises(ValueError):
            validate_indicator("44d88612fea8a8f36de82e1278abb02")  # 31 chars


# ── SHA-1 hash ────────────────────────────────────────────────────────────────

class TestSHA1:
    def test_valid_sha1(self):
        h = "3395856ce81f2b7382dee72602f798b642f14d0"
        _, ioc_type = validate_indicator(h)
        assert ioc_type == "sha1"

    def test_sha1_wrong_length_rejected(self):
        with pytest.raises(ValueError):
            validate_indicator("3395856ce81f2b7382dee72602f798b642f14d")  # 39 chars


# ── SHA-256 hash ──────────────────────────────────────────────────────────────

class TestSHA256:
    def test_valid_sha256(self):
        h = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        _, ioc_type = validate_indicator(h)
        assert ioc_type == "sha256"

    def test_sha256_wrong_length_rejected(self):
        with pytest.raises(ValueError):
            validate_indicator("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0")


# ── Empty / None input ────────────────────────────────────────────────────────

class TestInvalidInput:
    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_indicator("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_indicator("   ")

    def test_random_garbage_raises(self):
        with pytest.raises(ValueError, match="Unrecognised"):
            validate_indicator("not_an_ioc!!")

    def test_url_rejected(self):
        with pytest.raises(ValueError):
            validate_indicator("http://evil.com/payload")
