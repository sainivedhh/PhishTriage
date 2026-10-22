"""Header authentication analysis: SPF, DKIM, DMARC, address mismatches, and Received-chain anomalies."""
from __future__ import annotations

from email.utils import parseaddr
import re
from typing import List, Optional, Tuple

import tldextract

from phishtriage.models import HeaderAuthResult, ParsedEmail


class HeaderAuthenticator:
    """Analyzes email authentication headers, address alignment, and transmission hops."""

    def __init__(self) -> None:
        self.extractor = tldextract.TLDExtract(suffix_list_urls=None)

    def analyze(self, email: ParsedEmail) -> HeaderAuthResult:
        auth_results_raw = self._get_first_header(email, "Authentication-Results")
        spf, dkim, dmarc = self._parse_auth_results(auth_results_raw)

        # Fallback to Received-SPF if SPF was not in Authentication-Results
        if not spf:
            received_spf = self._get_first_header(email, "Received-SPF")
            if received_spf:
                spf = self._parse_received_spf(received_spf)

        # Fallback to DKIM-Signature check
        if not dkim:
            dkim_sig = self._get_first_header(email, "DKIM-Signature")
            if not dkim_sig:
                dkim = "none"

        # Fallback to ARC-Authentication-Results
        if not (spf and dkim and dmarc):
            arc_results = self._get_first_header(email, "ARC-Authentication-Results")
            if arc_results:
                a_spf, a_dkim, a_dmarc = self._parse_auth_results(arc_results)
                spf = spf or a_spf
                dkim = dkim or a_dkim
                dmarc = dmarc or a_dmarc

        from_domain = self._extract_domain(email.from_address)
        return_path_address = self._extract_address(email.return_path) if email.return_path else None
        return_path_domain = self._extract_domain(return_path_address) if return_path_address else None
        reply_to_address = self._extract_address(email.reply_to) if email.reply_to else None
        reply_to_domain = self._extract_domain(reply_to_address) if reply_to_address else None

        mismatches: List[str] = []
        if return_path_domain and from_domain and return_path_domain != from_domain:
            mismatches.append(f"Return-Path domain ({return_path_domain}) does not match From domain ({from_domain})")

        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            mismatches.append(f"Reply-To domain ({reply_to_domain}) does not match From domain ({from_domain})")

        # Received header chain analysis
        received_headers = email.headers.get("Received", [])
        received_hops = len(received_headers)
        received_anomalies = self._analyze_received_chain(received_headers)

        return HeaderAuthResult(
            spf=spf or "none",
            dkim=dkim or "none",
            dmarc=dmarc or "none",
            auth_results_raw=auth_results_raw,
            from_header=email.from_header,
            from_address=email.from_address,
            from_domain=from_domain,
            return_path=email.return_path,
            return_path_domain=return_path_domain,
            reply_to=email.reply_to,
            reply_to_domain=reply_to_domain,
            mismatches=mismatches,
            received_hops=received_hops,
            received_anomalies=received_anomalies,
        )

    def _get_first_header(self, email: ParsedEmail, header_name: str) -> Optional[str]:
        for k, v in email.headers.items():
            if k.lower() == header_name.lower() and v:
                return v[0]
        return None

    def _parse_auth_results(self, raw_header: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        if not raw_header:
            return None, None, None

        raw = raw_header.lower()

        # Parse spf=...
        spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b", raw)
        spf = spf_match.group(1) if spf_match else None

        # Parse dkim=...
        dkim_match = re.search(r"\bdkim=(pass|fail|neutral|none|permerror|temperror)\b", raw)
        dkim = dkim_match.group(1) if dkim_match else None

        # Parse dmarc=...
        dmarc_match = re.search(r"\bdmarc=(pass|fail|action|none|temperror|permerror)\b", raw)
        dmarc = dmarc_match.group(1) if dmarc_match else None

        return spf, dkim, dmarc

    def _parse_received_spf(self, raw: str) -> Optional[str]:
        raw_l = raw.lower()
        for verdict in ["pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"]:
            if raw_l.startswith(verdict) or f" {verdict} " in raw_l:
                return verdict
        return None

    def _extract_address(self, header_val: Optional[str]) -> Optional[str]:
        if not header_val:
            return None
        _, addr = parseaddr(header_val)
        return addr or None

    def _extract_domain(self, address: Optional[str]) -> Optional[str]:
        if not address or "@" not in address:
            return None
        raw_domain = address.split("@")[-1].strip().lower()
        ext = self.extractor(raw_domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return raw_domain

    def _analyze_received_chain(self, received_headers: List[str]) -> List[str]:
        anomalies: List[str] = []
        if not received_headers:
            anomalies.append("Missing Received headers in message")
            return anomalies

        # Check for reserved/private IP injection in intermediate or first hop
        for idx, hop in enumerate(received_headers):
            hop_lower = hop.lower()
            # Suspicious dynamic DNS or residential broadband in relay
            if re.search(r"\b(dynamic|res|broadband|dsl|dialup|pool|cable)\.[\w.-]+\b", hop_lower):
                anomalies.append(f"Received hop #{idx+1} references dialup/residential relay host")
            # Forged/fake localhost or suspicious localhost claiming external domain
            if "localhost" in hop_lower and "by mx." in hop_lower:
                anomalies.append(f"Received hop #{idx+1} shows localhost pretending to be external MX")

        return anomalies
