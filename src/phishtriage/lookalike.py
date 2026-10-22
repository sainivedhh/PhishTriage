"""Lookalike domain detection using Levenshtein distance, Jaro-Winkler, and Homoglyph/IDN Punycode checks."""
from __future__ import annotations

import unicodedata
from typing import Dict, List, Optional
from pydantic import BaseModel
import rapidfuzz.distance
import tldextract


# Common Cyrillic, Greek, and Latin confusable homoglyphs mapped to ASCII equivalents
HOMOGLYPH_MAP: Dict[str, str] = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ո": "n",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "υ": "u", "χ": "x",
    "0": "o", "1": "l", "l": "1", "vv": "w",
}


class LookalikeMatch(BaseModel):
    suspect_domain: str
    target_domain: str
    match_type: str  # 'homoglyph_punycode', 'levenshtein', 'jaro_winkler'
    similarity_score: float
    details: str


class LookalikeDetector:
    """Detects typosquatting, combosquatting, and IDN homoglyphs against protected domains."""

    def __init__(
        self,
        protected_domains: Optional[List[str]] = None,
        levenshtein_threshold: int = 2,
        jaro_winkler_threshold: float = 0.88,
    ) -> None:
        self.protected_domains = [d.lower().strip() for d in (protected_domains or ["google.com", "microsoft.com", "apple.com", "paypal.com", "corporate.com"])]
        self.levenshtein_threshold = levenshtein_threshold
        self.jaro_winkler_threshold = jaro_winkler_threshold
        self.extractor = tldextract.TLDExtract(suffix_list_urls=None)

    def extract_base_domain(self, domain_or_url: str) -> str:
        domain = domain_or_url.strip().lower()
        if "@" in domain:
            domain = domain.split("@")[-1]
        ext = self.extractor(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain or domain

    def check_domain(self, suspect_domain: str) -> List[LookalikeMatch]:
        base_suspect = self.extract_base_domain(suspect_domain)
        if not base_suspect:
            return []

        # If it is identical to a protected domain, it is legitimately that domain (not a lookalike)
        if base_suspect in self.protected_domains:
            return []

        matches: List[LookalikeMatch] = []

        # 1. Punycode / IDN / Homoglyph check
        decoded_suspect = base_suspect
        if base_suspect.startswith("xn--") or ".xn--" in base_suspect:
            try:
                decoded_suspect = base_suspect.encode("ascii").decode("idna")
            except Exception:
                decoded_suspect = base_suspect

        normalized_suspect = self._normalize_homoglyphs(decoded_suspect)

        for target in self.protected_domains:
            # Check normalized homoglyph equivalence
            target_norm = self._normalize_homoglyphs(target)
            if normalized_suspect == target_norm and base_suspect != target:
                matches.append(
                    LookalikeMatch(
                        suspect_domain=base_suspect,
                        target_domain=target,
                        match_type="homoglyph_punycode",
                        similarity_score=1.0,
                        details=f"Homoglyph/IDN spoof of protected domain '{target}' (punycode/normalized: {normalized_suspect})",
                    )
                )
                continue

            # Check distance metrics on the domain label (e.g. 'paypal' in 'paypal.com')
            suspect_core = self._get_core_label(base_suspect)
            target_core = self._get_core_label(target)

            if not suspect_core or not target_core:
                continue

            # Exact match of core on different TLD (e.g., paypal.top vs paypal.com)
            if suspect_core == target_core and base_suspect != target:
                matches.append(
                    LookalikeMatch(
                        suspect_domain=base_suspect,
                        target_domain=target,
                        match_type="tld_swap",
                        similarity_score=0.95,
                        details=f"Protected brand '{target_core}' registered under untrusted or alternative TLD '{base_suspect}'",
                    )
                )
                continue

            # Levenshtein distance check
            lev_dist = rapidfuzz.distance.Levenshtein.distance(suspect_core, target_core)
            if 0 < lev_dist <= self.levenshtein_threshold and len(suspect_core) >= 4:
                similarity = 1.0 - (lev_dist / max(len(suspect_core), len(target_core)))
                matches.append(
                    LookalikeMatch(
                        suspect_domain=base_suspect,
                        target_domain=target,
                        match_type="levenshtein",
                        similarity_score=round(similarity, 3),
                        details=f"Levenshtein distance of {lev_dist} against '{target}'",
                    )
                )
                continue

            # Jaro-Winkler similarity check
            jw_sim = rapidfuzz.distance.JaroWinkler.similarity(suspect_core, target_core)
            if jw_sim >= self.jaro_winkler_threshold and suspect_core != target_core:
                matches.append(
                    LookalikeMatch(
                        suspect_domain=base_suspect,
                        target_domain=target,
                        match_type="jaro_winkler",
                        similarity_score=round(jw_sim, 3),
                        details=f"High Jaro-Winkler similarity ({jw_sim:.3f}) with protected '{target}'",
                    )
                )

        return matches

    def _get_core_label(self, domain: str) -> str:
        ext = self.extractor(domain)
        return ext.domain.lower() if ext.domain else domain.split(".")[0].lower()

    def _normalize_homoglyphs(self, text: str) -> str:
        # Normalize unicode NFKD
        nfkd = unicodedata.normalize("NFKD", text)
        result = []
        for char in nfkd:
            c_low = char.lower()
            result.append(HOMOGLYPH_MAP.get(c_low, c_low))
        return "".join(result)
