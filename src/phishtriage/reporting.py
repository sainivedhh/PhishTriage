"""Incident Report Generator (Markdown & IOC JSON Export)."""
from __future__ import annotations

import json
from typing import Any, Dict

from phishtriage.models import IncidentReport


class ReportGenerator:
    """Produces detailed Markdown incident reports and standalone JSON IOC exports."""

    @staticmethod
    def generate_markdown(report: IncidentReport) -> str:
        lines = []
        lines.append(f"# Incident Report: {report.incident_id}")
        lines.append("")
        lines.append(f"**Date (UTC)**: {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Verdict**: `{report.verdict.value.upper()}`")
        lines.append(f"**Risk Score**: **{report.score} / 100**")
        lines.append(f"**Subject**: {report.email_subject}")
        lines.append(f"**Sender**: `{report.sender}`")
        lines.append(f"**Recipient(s)**: `{report.recipient}`")
        lines.append("")

        # Executive Summary / LLM Triage
        lines.append("## Executive Summary")
        if report.llm_analysis:
            lines.append(f"> {report.llm_analysis.executive_assessment}")
            lines.append("")
            lines.append(f"**Summary**: {report.llm_analysis.summary}")
        else:
            lines.append("No automated summary available.")
        lines.append("")

        # MITRE ATT&CK Mapping
        lines.append("## MITRE ATT&CK Techniques")
        if report.mitre_techniques:
            for tech in report.mitre_techniques:
                lines.append(f"- **{tech}**")
        else:
            lines.append("No MITRE ATT&CK techniques observed (benign baseline).")
        lines.append("")

        # Rule Findings & Score Breakdown
        lines.append("## Detection Rules & Score Breakdown")
        if report.score_breakdown:
            lines.append("| Rule ID | Title | Severity | Score Contribution | ATT&CK | Description |")
            lines.append("| :--- | :--- | :--- | :---: | :---: | :--- |")
            for f in report.score_breakdown:
                att_id = f.mitre_attack_id or "N/A"
                lines.append(
                    f"| `{f.rule_id}` | {f.title} | `{f.severity.value.upper()}` | +{f.score_contribution} | `{att_id}` | {f.description} |"
                )
        else:
            lines.append("No detection rules triggered.")
        lines.append("")

        # Extracted IOCs
        lines.append("## Extracted Indicators of Compromise (IOCs)")
        has_iocs = False
        for category, items in report.iocs.items():
            if items:
                has_iocs = True
                lines.append(f"### {category.capitalize()} ({len(items)})")
                for item in items:
                    lines.append(f"- `{item}`")
        if not has_iocs:
            lines.append("No external indicators identified.")
        lines.append("")

        # Recommended Response Actions
        lines.append("## Recommended Incident Response Actions")
        if report.recommended_actions:
            for idx, action in enumerate(report.recommended_actions, start=1):
                lines.append(f"{idx}. {action}")
        else:
            lines.append("No specific response actions required.")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def export_iocs_json(report: IncidentReport) -> str:
        data: Dict[str, Any] = {
            "incident_id": report.incident_id,
            "verdict": report.verdict.value,
            "score": report.score,
            "timestamp": report.created_at.isoformat(),
            "iocs": report.iocs,
        }
        return json.dumps(data, indent=2)
