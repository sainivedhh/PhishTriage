"""Unit tests for Module 7 Detection Rules & Module 8 Risk Engine."""
from phishtriage.models import FindingSeverity, Verdict
from phishtriage.risk_engine import RiskEngine, RuleEngine


def test_rule_engine_evaluation(tmp_path):
    rules_yaml = """
- id: TEST-001
  title: Test DMARC Fail
  severity: high
  score: 35
  mitre_attack_id: T1566.002
  description: Test description
  condition:
    field: header_auth.dmarc
    in: ["fail"]
"""
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(rules_yaml)

    engine = RuleEngine(rules_file)
    context = {
        "header_auth": {
            "dmarc": "fail"
        }
    }

    findings = engine.evaluate(context)
    assert len(findings) == 1
    assert findings[0].rule_id == "TEST-001"
    assert findings[0].score_contribution == 35
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].mitre_attack_id == "T1566.002"


def test_risk_engine_scoring_and_verdict():
    risk_engine = RiskEngine(suspicious_threshold=25, malicious_threshold=50)

    # 1. Benign case
    benign_score = risk_engine.calculate_risk([])
    assert benign_score.total_score == 0
    assert benign_score.verdict == Verdict.BENIGN
    assert len(benign_score.mitre_techniques) == 0

    # 2. Suspicious case
    engine = RuleEngine("rules/detection_rules.yaml")
    context_suspicious = {
        "header_auth": {"spf": "pass", "dmarc": "pass", "mismatches": [], "received_anomalies": []},
        "url_findings": [{"indicator_type": "url_shortener"}],
        "lookalike_matches": [],
        "attachment_findings": [],
        "body_findings": [{"finding_type": "urgency_language"}],
    }
    findings_suspicious = engine.evaluate(context_suspicious)
    score_suspicious = risk_engine.calculate_risk(findings_suspicious)
    # url_shortener (15) + urgency_language (15) = 30 -> SUSPICIOUS
    assert score_suspicious.total_score == 30
    assert score_suspicious.verdict == Verdict.SUSPICIOUS

    # 3. Malicious case
    context_malicious = {
        "header_auth": {"spf": "pass", "dmarc": "pass", "mismatches": [], "received_anomalies": []},
        "url_findings": [],
        "lookalike_matches": [],
        "attachment_findings": [{"finding_type": "known_malicious_hash"}],  # 50 pts
        "body_findings": [],
    }
    findings_malicious = engine.evaluate(context_malicious)
    score_malicious = risk_engine.calculate_risk(findings_malicious)
    assert score_malicious.total_score >= 50
    assert score_malicious.verdict == Verdict.MALICIOUS
    assert "T1566.001" in score_malicious.mitre_techniques
