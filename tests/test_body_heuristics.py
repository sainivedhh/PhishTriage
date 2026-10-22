"""Unit tests for Module 6 Body Heuristics and BEC."""
from phishtriage.body_heuristics import BodyHeuristicsAnalyzer
from phishtriage.models import ParsedEmail


def test_bec_executive_impersonation_and_wire():
    analyzer = BodyHeuristicsAnalyzer(
        vip_names=["Jane Smith", "CEO"],
        protected_domains=["corporate.com"],
    )

    email = ParsedEmail(
        from_header="Jane Smith <ceo-office-update@gmail.com>",
        from_name="Jane Smith",
        from_address="ceo-office-update@gmail.com",
        subject="URGENT: Confidential Wire Transfer",
        body_plain="Hi finance team,\nI am in a meeting. Please process an urgent wire transfer to the new vendor. Keep this strictly confidential.",
    )

    findings = analyzer.analyze(email)
    types = [f.finding_type for f in findings]
    assert "executive_impersonation" in types
    assert "urgency_language" in types
    assert "financial_request" in types


def test_credential_phishing_urgency():
    analyzer = BodyHeuristicsAnalyzer()

    email = ParsedEmail(
        from_header="Helpdesk <support@it-services.net>",
        from_name="Helpdesk",
        from_address="support@it-services.net",
        subject="Action Required: Password Expired",
        body_plain="Your password has expired. Click here to login and reset your password within 24 hours.",
    )

    findings = analyzer.analyze(email)
    types = [f.finding_type for f in findings]
    assert "urgency_language" in types
    assert "credential_harvesting_lure" in types


def test_benign_internal_vip_email():
    analyzer = BodyHeuristicsAnalyzer(
        vip_names=["Jane Smith"],
        protected_domains=["corporate.com"],
    )

    email = ParsedEmail(
        from_header="Jane Smith <jane.smith@corporate.com>",
        from_name="Jane Smith",
        from_address="jane.smith@corporate.com",
        subject="Team lunch tomorrow",
        body_plain="Hey team, let's meet tomorrow at noon for lunch. No agenda, just catching up.",
    )

    findings = analyzer.analyze(email)
    assert len(findings) == 0
