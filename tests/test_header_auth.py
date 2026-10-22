"""Unit tests for Module 2 Header Authentication."""
from email.message import EmailMessage
from phishtriage.header_auth import HeaderAuthenticator
from phishtriage.parser import EmlParser


def test_header_auth_valid_alignment():
    msg = EmailMessage()
    msg["From"] = "Alice <alice@company.com>"
    msg["Return-Path"] = "<alice@company.com>"
    msg["Reply-To"] = "Alice <alice@company.com>"
    msg["Authentication-Results"] = "mx.google.com; dkim=pass header.i=@company.com; spf=pass smtp.mailfrom=alice@company.com; dmarc=pass"
    msg["Received"] = "from mail.company.com by mx.google.com with ESMTPS; Mon, 20 Oct 2026 10:00:00 +0000"
    msg.set_content("All clean.")

    parser = EmlParser()
    email = parser.parse_bytes(msg.as_bytes())

    authenticator = HeaderAuthenticator()
    result = authenticator.analyze(email)

    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert len(result.mismatches) == 0
    assert result.received_hops == 1
    assert len(result.received_anomalies) == 0


def test_header_auth_spf_fail_and_mismatches():
    msg = EmailMessage()
    msg["From"] = "CEO <ceo@megacorp.com>"
    msg["Return-Path"] = "<spammer@evil-relay.org>"
    msg["Reply-To"] = "Offshore Ops <wire-department@external-scam.net>"
    msg["Authentication-Results"] = "mx.google.com; spf=fail (google.com: domain of evil-relay.org does not designate 1.2.3.4 as permitted sender); dkim=fail; dmarc=fail"
    msg["Received"] = "from pool-123-45.dynamic.broadband.telecom.net by relay.evil-relay.org"
    msg.set_content("Please execute urgent wire.")

    parser = EmlParser()
    email = parser.parse_bytes(msg.as_bytes())

    authenticator = HeaderAuthenticator()
    result = authenticator.analyze(email)

    assert result.spf == "fail"
    assert result.dkim == "fail"
    assert result.dmarc == "fail"
    assert len(result.mismatches) == 2  # Return-Path != From, Reply-To != From
    assert any("evil-relay.org" in m for m in result.mismatches)
    assert any("external-scam.net" in m for m in result.mismatches)
    assert len(result.received_anomalies) >= 1
