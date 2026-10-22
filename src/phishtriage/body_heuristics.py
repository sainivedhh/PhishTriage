"""Body heuristics: urgency language, financial/wire requests, credential harvesting, and VIP impersonation (BEC)."""
from __future__ import annotations

import re
from typing import List, Optional
from pydantic import BaseModel

from phishtriage.models import ParsedEmail


class BodyFinding(BaseModel):
    finding_type: str
    matched_text: str
    description: str
    severity: str  # high, medium, low


class BodyHeuristicsAnalyzer:
    """Detects social engineering triggers, urgency cues, BEC patterns, and executive impersonation."""

    def __init__(
        self,
        vip_names: Optional[List[str]] = None,
        protected_domains: Optional[List[str]] = None,
    ) -> None:
        self.vip_names = [v.lower().strip() for v in (vip_names or ["ceo", "cfo", "john doe", "jane smith", "chief executive"])]
        self.protected_domains = [d.lower().strip() for d in (protected_domains or ["corporate.com"])]

        # Compiled regex patterns for linguistic heuristics
        self.urgency_patterns = [
            (re.compile(r"\b(immediate(?:ly)?|urgent(?:ly)?|action required|within 24 hours|account suspended|final notice|critical alert)\b", re.I), "Urgency / Pressure indicator"),
            (re.compile(r"\b(password expired|security notice|unauthorized login|verify your identity|unusual activity)\b", re.I), "Security panic indicator"),
        ]

        self.financial_patterns = [
            (re.compile(r"\b(wire transfer|bank details|new bank account|routing number|swift code|invoice payment|gift cards?|itunes card|direct deposit)\b", re.I), "Financial transfer / Payment redirection request"),
            (re.compile(r"\b(confidential transaction|strictly confidential|keep this between us|do not call me|i am in a meeting)\b", re.I), "Secrecy & communication suppression"),
        ]

        self.credential_patterns = [
            (re.compile(r"\b(click here to login|update your credentials|reset your password|confirm your account|re-enter your password)\b", re.I), "Credential harvesting call-to-action"),
        ]

    def analyze(self, email: ParsedEmail) -> List[BodyFinding]:
        findings: List[BodyFinding] = []
        full_text = f"{email.subject}\n{email.body_plain}\n{email.body_html}"

        # 1. Linguistic urgency detection
        for pattern, desc in self.urgency_patterns:
            match = pattern.search(full_text)
            if match:
                findings.append(
                    BodyFinding(
                        finding_type="urgency_language",
                        matched_text=match.group(0),
                        description=f"{desc}: matched '{match.group(0)}'",
                        severity="medium",
                    )
                )

        # 2. Financial / Wire / Payment manipulation
        for pattern, desc in self.financial_patterns:
            match = pattern.search(full_text)
            if match:
                findings.append(
                    BodyFinding(
                        finding_type="financial_request",
                        matched_text=match.group(0),
                        description=f"{desc}: matched '{match.group(0)}'",
                        severity="high",
                    )
                )

        # 3. Credential harvest lures
        for pattern, desc in self.credential_patterns:
            match = pattern.search(full_text)
            if match:
                findings.append(
                    BodyFinding(
                        finding_type="credential_harvesting_lure",
                        matched_text=match.group(0),
                        description=f"{desc}: matched '{match.group(0)}'",
                        severity="high",
                    )
                )

        # 4. BEC: VIP / Executive Display-Name Impersonation
        # Scenario: From display name contains a VIP name, but From address domain is NOT an authorized corporate domain
        from_name_lower = (email.from_name or "").lower()
        from_addr_lower = (email.from_address or "").lower()
        sender_domain = from_addr_lower.split("@")[-1] if "@" in from_addr_lower else ""

        for vip in self.vip_names:
            if vip in from_name_lower:
                # If sender domain is not one of our protected internal corporate domains
                if not any(sender_domain.endswith(corp) for corp in self.protected_domains):
                    findings.append(
                        BodyFinding(
                            finding_type="executive_impersonation",
                            matched_text=f"Display Name: '{email.from_name}', Sender Address: '{email.from_address}'",
                            description=f"Executive Impersonation (BEC): Display name matches VIP '{vip}', but sent from external untrusted domain '{sender_domain}'.",
                            severity="high",
                        )
                    )
                break

        return findings
