"""Detection-as-Code Rule Engine and Risk Scoring Engine."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml

from phishtriage.models import Finding, FindingSeverity, RiskScore, Verdict


class RuleEngine:
    """Loads Sigma-style YAML detection rules and evaluates modular signals against them."""

    def __init__(self, rules_file: Optional[str | Path] = None) -> None:
        self.rules: List[Dict[str, Any]] = []
        if rules_file:
            path = Path(rules_file)
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    self.rules = yaml.safe_load(f) or []
            else:
                self.rules = []

    def evaluate(self, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        for rule in self.rules:
            rule_id = rule.get("id", "UNKNOWN")
            title = rule.get("title", "")
            severity_str = rule.get("severity", "medium").lower()
            severity = FindingSeverity(severity_str) if severity_str in FindingSeverity._value2member_map_ else FindingSeverity.MEDIUM
            score = rule.get("score", 10)
            mitre_id = rule.get("mitre_attack_id")
            description = rule.get("description", "")
            cond = rule.get("condition", {})

            if self._matches_condition(cond, context):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        score_contribution=score,
                        mitre_attack_id=mitre_id,
                        description=description,
                        evidence={"condition_field": cond.get("field")},
                    )
                )

        return findings

    def _matches_condition(self, cond: Dict[str, Any], context: Dict[str, Any]) -> bool:
        field_path = cond.get("field", "")
        if not field_path:
            return False

        # Resolve dotted field path in context
        val = context
        for part in field_path.split("."):
            if isinstance(val, dict):
                val = val.get(part)
            else:
                val = None
                break

        if val is None:
            return False

        # 1. Exact 'in' check
        if "in" in cond:
            allowed = cond["in"]
            if isinstance(val, str) and val in allowed:
                return True
            if isinstance(val, list) and any(v in allowed for v in val):
                return True

        # 2. Substring check
        if "has_substring" in cond:
            substr = cond["has_substring"].lower()
            if isinstance(val, str) and substr in val.lower():
                return True
            if isinstance(val, list) and any(substr in str(x).lower() for x in val):
                return True

        # 3. Minimum count
        if "min_count" in cond:
            if isinstance(val, (list, set, tuple)) and len(val) >= cond["min_count"]:
                return True

        # 4. Custom matching for structured sub-objects (lookalike, url, attachment, body findings)
        if "match_type_in" in cond:
            # val is list of LookalikeMatch
            target_types = cond["match_type_in"]
            if isinstance(val, list):
                for item in val:
                    m_type = getattr(item, "match_type", None) or (item.get("match_type") if isinstance(item, dict) else None)
                    if m_type in target_types:
                        return True

        if "indicator_type_in" in cond:
            # val is list of URLFinding
            target_types = cond["indicator_type_in"]
            if isinstance(val, list):
                for item in val:
                    ind_type = getattr(item, "indicator_type", None) or (item.get("indicator_type") if isinstance(item, dict) else None)
                    if ind_type in target_types:
                        return True

        if "finding_type_in" in cond:
            # val is list of AttachmentFinding or BodyFinding
            target_types = cond["finding_type_in"]
            if isinstance(val, list):
                for item in val:
                    f_type = getattr(item, "finding_type", None) or (item.get("finding_type") if isinstance(item, dict) else None)
                    if f_type in target_types:
                        return True

        return False


class RiskEngine:
    """Combines individual findings into an explainable 0-100 score and assigns a security verdict."""

    def __init__(self, suspicious_threshold: int = 25, malicious_threshold: int = 50) -> None:
        self.suspicious_threshold = suspicious_threshold
        self.malicious_threshold = malicious_threshold

    def calculate_risk(self, findings: List[Finding]) -> RiskScore:
        # Sum of score contributions capped at 100
        raw_score = sum(f.score_contribution for f in findings)
        total_score = min(max(raw_score, 0), 100)

        # Collect unique MITRE ATT&CK techniques
        mitre_set: Set[str] = set()
        for f in findings:
            if f.mitre_attack_id:
                mitre_set.add(f.mitre_attack_id)

        # Verdict calculation
        if total_score >= self.malicious_threshold:
            verdict = Verdict.MALICIOUS
        elif total_score >= self.suspicious_threshold:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN

        return RiskScore(
            total_score=total_score,
            verdict=verdict,
            breakdown=findings,
            mitre_techniques=sorted(list(mitre_set)),
        )
