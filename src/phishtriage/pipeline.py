"""End-to-end PhishTriage pipeline orchestrator."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from phishtriage.attachment_triage import AttachmentTriager
from phishtriage.body_heuristics import BodyHeuristicsAnalyzer
from phishtriage.header_auth import HeaderAuthenticator
from phishtriage.llm_triage import LLMTriager
from phishtriage.lookalike import LookalikeDetector
from phishtriage.models import Finding, IncidentReport, ParsedEmail, RiskScore
from phishtriage.parser import EmlParser
from phishtriage.risk_engine import RiskEngine, RuleEngine
from phishtriage.storage import Storage
from phishtriage.url_analysis import URLAnalyzer


class PhishTriagePipeline:
    """Orchestrates all parsing, deterministic detection modules, risk scoring, and report generation."""

    def __init__(
        self,
        rules_path: str = "rules/detection_rules.yaml",
        blocklist_path: str = "blocklist_hashes.txt",
        db_path: str = "phishtriage.db",
        protected_domains: Optional[List[str]] = None,
        vip_names: Optional[List[str]] = None,
        llm_api_key: Optional[str] = None,
    ) -> None:
        self.protected_domains = protected_domains or ["corporate.com", "google.com", "microsoft.com", "apple.com", "paypal.com"]
        self.vip_names = vip_names or ["Jane Smith", "John Doe", "CEO", "CFO"]

        self.parser = EmlParser()
        self.authenticator = HeaderAuthenticator()
        self.lookalike_detector = LookalikeDetector(protected_domains=self.protected_domains)
        self.url_analyzer = URLAnalyzer()
        self.attachment_triager = AttachmentTriager(blocklist_file=blocklist_path)
        self.body_analyzer = BodyHeuristicsAnalyzer(vip_names=self.vip_names, protected_domains=self.protected_domains)
        self.rule_engine = RuleEngine(rules_file=rules_path)
        self.risk_engine = RiskEngine()
        self.llm_triager = LLMTriager(api_key=llm_api_key)
        self.storage = Storage(db_path=db_path)

    def process_email_bytes(self, raw_bytes: bytes, filename: Optional[str] = None) -> IncidentReport:
        parsed: ParsedEmail = self.parser.parse_bytes(raw_bytes)
        return self._evaluate_parsed_email(parsed, filename)

    def process_file(self, file_path: str | Path) -> IncidentReport:
        path = Path(file_path)
        with open(path, "rb") as f:
            raw_bytes = f.read()
        return self.process_email_bytes(raw_bytes, filename=path.name)

    def _evaluate_parsed_email(self, email: ParsedEmail, filename: Optional[str] = None) -> IncidentReport:
        # 1. Header Authentication Analysis
        header_auth = self.authenticator.analyze(email)
        email.header_auth = header_auth

        # 2. Lookalike Domain Analysis (Check sender domain + link domains)
        lookalike_matches = []
        if header_auth.from_domain:
            lookalike_matches.extend(self.lookalike_detector.check_domain(header_auth.from_domain))
        if header_auth.return_path_domain and header_auth.return_path_domain != header_auth.from_domain:
            lookalike_matches.extend(self.lookalike_detector.check_domain(header_auth.return_path_domain))

        for u in email.urls:
            if u.domain:
                lookalike_matches.extend(self.lookalike_detector.check_domain(u.domain))

        # 3. URL Analysis
        url_findings = self.url_analyzer.analyze_urls(email.urls)

        # 4. Attachment Triage
        attachment_findings = self.attachment_triager.triage(email.attachments)

        # 5. Body Heuristics & BEC Analysis
        body_findings = self.body_analyzer.analyze(email)

        # 6. Build evaluation context for RuleEngine
        context: Dict[str, Any] = {
            "header_auth": header_auth.model_dump(),
            "lookalike_matches": lookalike_matches,
            "url_findings": url_findings,
            "attachment_findings": attachment_findings,
            "body_findings": body_findings,
        }

        # 7. Evaluate Detection-as-Code rules
        findings: List[Finding] = self.rule_engine.evaluate(context)

        # 8. Compute Risk Score & Assign Verdict
        risk_score: RiskScore = self.risk_engine.calculate_risk(findings)

        # 9. LLM / Deterministic Fallback Triage
        llm_response = self.llm_triager.triage(
            risk_score=risk_score,
            sender=email.from_address or email.from_header,
            subject=email.subject,
        )

        # 10. Extract IOCs
        iocs: Dict[str, List[str]] = {
            "domains": list(set(
                ([header_auth.from_domain] if header_auth.from_domain else []) +
                ([header_auth.return_path_domain] if header_auth.return_path_domain else []) +
                [u.domain for u in email.urls if u.domain]
            )),
            "ips": [u.url for u in email.urls if u.is_ip_address],
            "urls": [u.url for u in email.urls],
            "hashes": [a.sha256 for a in email.attachments],
            "senders": [email.from_address] if email.from_address else [],
        }

        # Generate unique incident ID
        inc_hash = hashlib.sha256(f"{email.message_id}_{email.subject}_{email.from_address}".encode()).hexdigest()[:12]
        incident_id = f"INC-{inc_hash.upper()}"

        report = IncidentReport(
            incident_id=incident_id,
            email_subject=email.subject,
            sender=email.from_header or email.from_address,
            recipient="; ".join(email.to_headers) if email.to_headers else "Undisclosed",
            verdict=risk_score.verdict,
            score=risk_score.total_score,
            score_breakdown=findings,
            mitre_techniques=risk_score.mitre_techniques,
            iocs=iocs,
            llm_analysis=llm_response,
            recommended_actions=llm_response.recommended_actions,
        )

        # Save to SQLite
        self.storage.save_incident(report)
        return report
