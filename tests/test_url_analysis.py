"""Unit tests for Module 4 URL Static Analysis."""
from phishtriage.models import ExtractedURL
from phishtriage.url_analysis import URLAnalyzer


def test_url_analyzer_flags_ip_and_shortener():
    analyzer = URLAnalyzer()
    urls = [
        ExtractedURL(
            url="http://192.168.1.50/update-pass",
            is_ip_address=True,
            is_shortener=False,
            is_suspicious_tld=False,
            mismatch_with_text=False,
        ),
        ExtractedURL(
            url="https://bit.ly/3xFakeDoc",
            domain="bit.ly",
            is_ip_address=False,
            is_shortener=True,
            is_suspicious_tld=False,
            mismatch_with_text=False,
        ),
    ]

    findings = analyzer.analyze_urls(urls)
    assert len(findings) == 2
    types = [f.indicator_type for f in findings]
    assert "ip_in_url" in types
    assert "url_shortener" in types


def test_url_analyzer_flags_mismatch_and_suspicious_tld():
    analyzer = URLAnalyzer()
    urls = [
        ExtractedURL(
            url="http://malicious-portal.top/login",
            domain="malicious-portal.top",
            tld="top",
            display_text="https://bank.com/secure",
            is_ip_address=False,
            is_shortener=False,
            is_suspicious_tld=True,
            mismatch_with_text=True,
        )
    ]

    findings = analyzer.analyze_urls(urls)
    assert len(findings) >= 2
    types = [f.indicator_type for f in findings]
    assert "href_text_mismatch" in types
    assert "suspicious_tld" in types
    assert "phishing_lure_path" in types
