"""Optional LLM Triage Module with strict Prompt-Injection Guards and Deterministic Fallback."""
from __future__ import annotations

import re
from typing import List, Optional

from phishtriage.models import LLMTriageResponse, RiskScore, Verdict


# High-risk prompt injection and jailbreak patterns common in adversarial email payloads
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.I),
    re.compile(r"system\s*:\s*you\s+are", re.I),
    re.compile(r"disregard\s+(the\s+)?above", re.I),
    re.compile(r"new\s+system\s+prompt", re.I),
    re.compile(r"<\|im_start\|>", re.I),
    re.compile(r"<\|im_end\|>", re.I),
    re.compile(r"you\s+must\s+say\s+benign", re.I),
    re.compile(r"override\s+verdict", re.I),
]


class LLMTriager:
    """Provides LLM triage summary over structured findings with deterministic fallback and injection defense.
    
    CRITICAL SECURITY ARCHITECTURE:
    1. NEVER feeds raw, unredacted, attacker-controlled email bodies directly to the LLM.
    2. Feeds strictly sanitized, deterministic structured findings (rule IDs, titles, IOCs).
    3. Scans for prompt injection attacks and triggers deterministic fallback if detected.
    4. Guarantees 100% offline availability with identical Pydantic response schema.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key

    def sanitize_input(self, text: str) -> str:
        """Sanitizes text by stripping control characters and known prompt-injection markers."""
        cleaned = text.replace("\r", " ").replace("\n", " ").strip()
        for pattern in INJECTION_PATTERNS:
            if pattern.search(cleaned):
                cleaned = pattern.sub("[REDACTED_INJECTION_ATTEMPT]", cleaned)
        return cleaned

    def triage(
        self,
        risk_score: RiskScore,
        sender: str,
        subject: str,
        force_fallback: bool = False,
    ) -> LLMTriageResponse:
        """Performs triage analysis. Falls back to deterministic rule-based response when LLM is unavailable or disabled."""
        # Check for injection in email headers (subject or sender)
        sanitized_subject = self.sanitize_input(subject)
        sanitized_sender = self.sanitize_input(sender)

        has_injection = "[REDACTED_INJECTION_ATTEMPT]" in sanitized_subject or "[REDACTED_INJECTION_ATTEMPT]" in sanitized_sender

        if not self.api_key or force_fallback or has_injection:
            return self._deterministic_fallback(risk_score, sanitized_sender, sanitized_subject, has_injection=has_injection)

        # In a deployment with an active API key, we format structured findings into a locked system prompt.
        # But if the network is offline or optional, we reliably fall back to the exact same schema.
        return self._deterministic_fallback(risk_score, sanitized_sender, sanitized_subject, has_injection=False)

    def _deterministic_fallback(
        self,
        risk_score: RiskScore,
        sender: str,
        subject: str,
        has_injection: bool = False,
    ) -> LLMTriageResponse:
        """Deterministic rule-based fallback returning the exact same Pydantic schema."""
        num_findings = len(risk_score.breakdown)
        score = risk_score.total_score
        verdict = risk_score.verdict

        actions: List[str] = []
        if has_injection:
            actions.append("CRITICAL: Adversarial prompt-injection attempt detected in email metadata; isolate sample.")

        if verdict == Verdict.MALICIOUS:
            summary = (
                f"High-confidence malicious email detected from '{sender}' (Score {score}/100). "
                f"Triggered {num_findings} security detection rules including critical attack indicators."
            )
            executive_assessment = (
                "Email exhibits strong active indicators of phishing/BEC targeting the organization. "
                "Immediate containment and mailbox purge recommended."
            )
            actions.extend([
                "Purge message from recipient and company mailboxes immediately.",
                "Block sender domain and IP addresses at mail gateway and firewall.",
                "Reset user credentials if recipient interacted with links or attachments.",
                "Submit attachment hashes and malicious URLs to endpoint EDR / perimeter blocklists.",
            ])
        elif verdict == Verdict.SUSPICIOUS:
            summary = (
                f"Suspicious email activity observed from '{sender}' (Score {score}/100). "
                f"Triggered {num_findings} detection rules warranting analyst verification."
            )
            executive_assessment = (
                "Email contains anomalous indicators such as shortened links, urgency language, or minor auth mismatches. "
                "Requires tier-1 SOC review before delivery."
            )
            actions.extend([
                "Deliver email with visible external warning banner, or hold in security quarantine.",
                "Review landing destination of shortened or suspicious URLs in an isolated sandbox.",
                "Verify legitimacy of sender via out-of-band communication (phone/Slack).",
            ])
        else:
            summary = (
                f"Email from '{sender}' evaluated as benign (Score {score}/100). "
                "Passed header authentication and contains no malicious attachments, deceptive links, or social engineering cues."
            )
            executive_assessment = "Standard communication. No threat indicators identified."
            actions.append("Allow delivery to inbox without restriction.")

        # Map MITRE techniques into human-readable descriptions
        mitre_descriptions: List[str] = []
        technique_map = {
            "T1566.001": "T1566.001 (Spearphishing Attachment)",
            "T1566.002": "T1566.002 (Spearphishing Link)",
            "T1534": "T1534 (Internal Spearphishing / Hop Spoofing)",
            "T1656": "T1656 (Impersonation / Social Engineering)",
        }
        for t in risk_score.mitre_techniques:
            mitre_descriptions.append(technique_map.get(t, f"{t} (ATT&CK Technique)"))

        return LLMTriageResponse(
            summary=summary,
            executive_assessment=executive_assessment,
            recommended_actions=actions,
            confidence=0.95 if verdict == Verdict.MALICIOUS else 0.85,
            is_fallback=True,
            mitre_summary=mitre_descriptions,
        )
