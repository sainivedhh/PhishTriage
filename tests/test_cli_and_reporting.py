"""Unit tests for reporting and CLI entrypoints."""
import json
from pathlib import Path
from typer.testing import CliRunner

from phishtriage.cli.main import app
from phishtriage.models import Finding, FindingSeverity, IncidentReport, Verdict
from phishtriage.reporting import ReportGenerator

runner = CliRunner()


def test_markdown_and_iocs_generation():
    report = IncidentReport(
        incident_id="INC-TEST123456",
        email_subject="Urgent Wire",
        sender="Jane Smith <ceo@gmail.com>",
        recipient="finance@corporate.com",
        verdict=Verdict.MALICIOUS,
        score=75,
        score_breakdown=[
            Finding(
                rule_id="BEC-001",
                title="VIP Impersonation",
                severity=FindingSeverity.CRITICAL,
                score_contribution=40,
                mitre_attack_id="T1656",
                description="VIP match",
            )
        ],
        mitre_techniques=["T1656"],
        iocs={"domains": ["gmail.com"], "ips": [], "urls": [], "hashes": [], "senders": ["ceo@gmail.com"]},
        recommended_actions=["Purge mailbox"],
    )

    md = ReportGenerator.generate_markdown(report)
    assert "# Incident Report: INC-TEST123456" in md
    assert "**Verdict**: `MALICIOUS`" in md
    assert "T1656" in md
    assert "`BEC-001`" in md

    iocs_json_str = ReportGenerator.export_iocs_json(report)
    iocs_data = json.loads(iocs_json_str)
    assert iocs_data["incident_id"] == "INC-TEST123456"
    assert "ceo@gmail.com" in iocs_data["iocs"]["senders"]


def test_cli_scan_and_report_command(tmp_path):
    db_file = tmp_path / "test.db"
    res = runner.invoke(
        app,
        ["scan", "data/synthetic_dataset/benign_corp_001.eml", "--db", str(db_file)],
    )
    assert res.exit_code == 0
    assert "BENIGN" in res.output

    # Read incident ID from database to test report command
    from phishtriage.storage import Storage
    storage = Storage(db_file)
    incidents = storage.list_incidents(1)
    assert len(incidents) == 1
    inc_id = incidents[0]["incident_id"]

    res_rep = runner.invoke(app, ["report", inc_id, "--db", str(db_file), "--format", "markdown"])
    assert res_rep.exit_code == 0
    assert inc_id in res_rep.output
