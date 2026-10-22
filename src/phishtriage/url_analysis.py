"""Static URL analyzer for phishing indicators (IP hosts, shorteners, mismatches, suspicious TLDs)."""
from __future__ import annotations

from typing import List
from pydantic import BaseModel

from phishtriage.models import ExtractedURL


class URLFinding(BaseModel):
    url: str
    indicator_type: str
    description: str
    severity: str  # high, medium, low


class URLAnalyzer:
    """Performs strictly static inspection of URLs without making external network requests."""

    def analyze_urls(self, urls: List[ExtractedURL]) -> List[URLFinding]:
        findings: List[URLFinding] = []

        for item in urls:
            # 1. IP-based URL
            if item.is_ip_address:
                findings.append(
                    URLFinding(
                        url=item.url,
                        indicator_type="ip_in_url",
                        description=f"Direct IP address host used in link target '{item.url}' to bypass domain reputation checks.",
                        severity="high",
                    )
                )

            # 2. Display text vs href mismatch
            if item.mismatch_with_text and item.display_text:
                findings.append(
                    URLFinding(
                        url=item.url,
                        indicator_type="href_text_mismatch",
                        description=f"Deceptive link: visible anchor text displayed '{item.display_text}' but navigates to '{item.url}'.",
                        severity="high",
                    )
                )

            # 3. Known URL Shortener
            if item.is_shortener:
                findings.append(
                    URLFinding(
                        url=item.url,
                        indicator_type="url_shortener",
                        description=f"URL shortener '{item.domain}' used to conceal true destination.",
                        severity="medium",
                    )
                )

            # 4. Suspicious TLD
            if item.is_suspicious_tld:
                findings.append(
                    URLFinding(
                        url=item.url,
                        indicator_type="suspicious_tld",
                        description=f"Link targets high-abuse / disposable TLD (.{item.tld}).",
                        severity="medium",
                    )
                )

            # 5. Excessive subdomains or login/credential keywords in path/subdomain
            subdomains_and_path = item.url.lower()
            if any(term in subdomains_and_path for term in ["login", "signin", "verify", "account-security", "webscr"]):
                findings.append(
                    URLFinding(
                        url=item.url,
                        indicator_type="phishing_lure_path",
                        description="Credential harvesting keywords identified in URL host or path prefix.",
                        severity="high",
                    )
                )

        return findings
