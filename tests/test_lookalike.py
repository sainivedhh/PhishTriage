"""Unit tests for Module 3 Lookalike Domain Detection."""
import pytest
from phishtriage.lookalike import LookalikeDetector


@pytest.fixture
def detector():
    return LookalikeDetector(
        protected_domains=["google.com", "microsoft.com", "apple.com", "paypal.com", "corporate.com"],
        levenshtein_threshold=2,
        jaro_winkler_threshold=0.88,
    )


def test_exact_protected_domain_not_flagged(detector):
    # Legitimate emails from protected domain should not flag themselves as lookalikes
    matches = detector.check_domain("corporate.com")
    assert len(matches) == 0

    matches_sub = detector.check_domain("mail.google.com")
    assert len(matches_sub) == 0


def test_typosquatting_levenshtein(detector):
    # 'paypa1.com' or 'paypall.com'
    matches = detector.check_domain("paypa1.com")
    assert len(matches) > 0
    assert any(m.target_domain == "paypal.com" for m in matches)

    matches_corp = detector.check_domain("corporat3.com")
    assert len(matches_corp) > 0
    assert any(m.target_domain == "corporate.com" for m in matches_corp)


def test_tld_swap(detector):
    # paypal.top instead of paypal.com
    matches = detector.check_domain("paypal.top")
    assert len(matches) > 0
    assert matches[0].match_type == "tld_swap"
    assert matches[0].target_domain == "paypal.com"


def test_punycode_and_homoglyphs(detector):
    # Cyrillic 'а' in apple.com -> xn--pple-43a.com or raw Cyrillic
    # 'а' is Cyrillic small letter a (U+0430)
    cyrillic_apple = "аpple.com"
    matches = detector.check_domain(cyrillic_apple)
    assert len(matches) > 0
    assert matches[0].match_type == "homoglyph_punycode"
    assert matches[0].target_domain == "apple.com"

    # Encoded punycode for Cyrillic 'аpple.com' is 'xn--pple-43d.com'
    puny_apple = "xn--pple-43d.com"
    matches_puny = detector.check_domain(puny_apple)
    assert len(matches_puny) > 0
    assert matches_puny[0].match_type == "homoglyph_punycode"
