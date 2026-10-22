"""End-to-end integration and fixture testing for PhishTriage."""
from phishtriage.models import Verdict
from phishtriage.pipeline import PhishTriagePipeline


def test_end_to_end_benign_email():
    pipeline = PhishTriagePipeline(db_path=":memory:")
    report = pipeline.process_file("data/synthetic_dataset/benign_corp_001.eml")

    assert report.verdict == Verdict.BENIGN
    assert report.score < 25
    assert len(report.mitre_techniques) == 0


def test_end_to_end_phishing_email():
    pipeline = PhishTriagePipeline(db_path=":memory:")
    report = pipeline.process_file("data/synthetic_dataset/phishing_credential_001.eml")

    assert report.verdict == Verdict.MALICIOUS
    assert report.score >= 50
    assert "T1566.002" in report.mitre_techniques
    assert len(report.score_breakdown) > 0


def test_end_to_end_bec_email():
    pipeline = PhishTriagePipeline(db_path=":memory:")
    report = pipeline.process_file("data/synthetic_dataset/bec_executive_001.eml")

    assert report.verdict == Verdict.MALICIOUS
    assert report.score >= 50
    assert "T1656" in report.mitre_techniques
    assert any("Jane Smith" in f.description or "Impersonation" in f.title for f in report.score_breakdown)
