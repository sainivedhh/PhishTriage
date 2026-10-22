"""MIME .eml parser extracting headers, body content, URLs, and attachment metadata."""
from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
import io
import re
from typing import List, Optional, Tuple
import zipfile

from bs4 import BeautifulSoup
import tldextract

from phishtriage.models import AttachmentMetadata, ExtractedURL, ParsedEmail

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))"""
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "loan", "club",
    "click", "country", "stream", "download", "racing", "win", "bid", "accountant",
    "vip", "rest", "buzz", "surf"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl",
    "rebrand.ly", "cutt.ly", "shorturl.at"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".ppsm", ".sldm"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar"
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".iso", ".img", ".jar"
}


class EmlParser:
    """Deterministic parser for raw .eml emails."""

    def __init__(self) -> None:
        # Use offline tldextract cache to avoid network calls during test/offline execution
        self.extractor = tldextract.TLDExtract(suffix_list_urls=None)

    def parse_bytes(self, raw_bytes: bytes) -> ParsedEmail:
        msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=policy.default)
        return self._build_parsed_email(msg, len(raw_bytes))

    def parse_file(self, file_path: str) -> ParsedEmail:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        return self.parse_bytes(raw_bytes)

    def _build_parsed_email(self, msg: EmailMessage, raw_size_bytes: int) -> ParsedEmail:
        # Extract basic headers
        from_header = str(msg.get("From", ""))
        from_name, from_address = parseaddr(from_header)
        
        to_headers = [str(x) for x in msg.get_all("To", [])]
        cc_headers = [str(x) for x in msg.get_all("Cc", [])]
        reply_to = str(msg.get("Reply-To", "")) if msg.get("Reply-To") else None
        return_path = str(msg.get("Return-Path", "")) if msg.get("Return-Path") else None
        
        parsed_date = None
        date_str = msg.get("Date")
        if date_str:
            try:
                parsed_date = parsedate_to_datetime(str(date_str))
            except Exception:
                parsed_date = None

        # Build raw headers map
        headers_dict: dict[str, list[str]] = {}
        for key, val in msg.items():
            headers_dict.setdefault(key, []).append(str(val))

        # Extract body parts
        body_plain, body_html = self._extract_bodies(msg)

        # Extract URLs from HTML (with href and display text) and plain text
        urls = self._extract_urls(body_plain, body_html)

        # Extract attachments
        attachments = self._extract_attachments(msg)

        return ParsedEmail(
            message_id=msg.get("Message-ID"),
            date=parsed_date,
            subject=str(msg.get("Subject", "")),
            from_header=from_header,
            from_address=from_address,
            from_name=from_name,
            to_headers=to_headers,
            cc_headers=cc_headers,
            reply_to=reply_to,
            return_path=return_path,
            headers=headers_dict,
            body_plain=body_plain,
            body_html=body_html,
            urls=urls,
            attachments=attachments,
            raw_size_bytes=raw_size_bytes,
        )

    def _extract_bodies(self, msg: EmailMessage) -> Tuple[str, str]:
        plain_parts: List[str] = []
        html_parts: List[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    continue
                ctype = part.get_content_type()
                try:
                    payload = part.get_content()
                    if not isinstance(payload, str):
                        payload = part.get_payload(decode=True)
                        if payload:
                            payload = payload.decode(errors="replace")
                        else:
                            payload = ""
                except Exception:
                    payload = ""

                if ctype == "text/plain":
                    plain_parts.append(payload)
                elif ctype == "text/html":
                    html_parts.append(payload)
        else:
            ctype = msg.get_content_type()
            try:
                payload = msg.get_content()
                if not isinstance(payload, str):
                    payload = msg.get_payload(decode=True)
                    payload = payload.decode(errors="replace") if payload else ""
            except Exception:
                payload = ""
            if ctype == "text/plain":
                plain_parts.append(payload)
            elif ctype == "text/html":
                html_parts.append(payload)

        return "\n".join(plain_parts), "\n".join(html_parts)

    def _extract_urls(self, text: str, html: str) -> List[ExtractedURL]:
        extracted_map: dict[str, ExtractedURL] = {}

        # 1. Parse HTML links (captures href & visible anchor text)
        if html:
            soup = BeautifulSoup(html, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                display = a_tag.get_text().strip()
                if href and href.startswith(("http://", "https://", "www.")):
                    norm_url = self._normalize_url(href)
                    extracted_map[norm_url] = self._analyze_single_url(norm_url, display_text=display)

        # 2. Parse raw regex from plain text & HTML text
        combined_text = f"{text}\n{html}"
        for match in URL_REGEX.finditer(combined_text):
            found_url = match.group(0).strip()
            if found_url.startswith(("http://", "https://", "www.")):
                norm_url = self._normalize_url(found_url)
                if norm_url not in extracted_map:
                    extracted_map[norm_url] = self._analyze_single_url(norm_url, display_text=None)

        return list(extracted_map.values())

    def _normalize_url(self, url: str) -> str:
        if url.startswith("www."):
            return "http://" + url
        return url

    def _analyze_single_url(self, url: str, display_text: Optional[str] = None) -> ExtractedURL:
        ext = self.extractor(url)
        domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else ext.domain.lower()
        tld = ext.suffix.lower()

        # Check if domain is an IPv4 address
        is_ip = bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ext.domain))
        is_shortener = domain in KNOWN_SHORTENERS
        is_suspicious_tld = tld in SUSPICIOUS_TLDS

        # Check href vs display text mismatch
        mismatch = False
        if display_text:
            disp_ext = self.extractor(display_text)
            if disp_ext.domain:
                disp_domain = f"{disp_ext.domain}.{disp_ext.suffix}".lower() if disp_ext.suffix else disp_ext.domain.lower()
                if disp_domain and domain and disp_domain != domain:
                    mismatch = True

        return ExtractedURL(
            url=url,
            display_text=display_text,
            domain=domain,
            tld=tld,
            is_ip_address=is_ip,
            is_shortener=is_shortener,
            is_suspicious_tld=is_suspicious_tld,
            mismatch_with_text=mismatch,
        )

    def _extract_attachments(self, msg: EmailMessage) -> List[AttachmentMetadata]:
        attachments: List[AttachmentMetadata] = []
        for part in msg.walk():
            filename = part.get_filename()
            content_disposition = str(part.get("Content-Disposition", ""))
            if not filename and "attachment" not in content_disposition:
                continue

            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            clean_filename = filename if filename else "unnamed_attachment"
            content_type = part.get_content_type()
            size_bytes = len(payload)
            md5_hash = hashlib.md5(payload).hexdigest()
            sha256_hash = hashlib.sha256(payload).hexdigest()

            # Analyze extension
            lower_name = clean_filename.lower()
            ext = "." + lower_name.split(".")[-1] if "." in lower_name else ""
            is_macro = ext in MACRO_EXTENSIONS
            is_archive = ext in ARCHIVE_EXTENSIONS
            
            # Double extension check (e.g., invoice.pdf.exe, doc.docx.scr)
            has_double = False
            parts = lower_name.split(".")
            if len(parts) > 2:
                last_ext = "." + parts[-1]
                if last_ext in EXECUTABLE_EXTENSIONS:
                    has_double = True

            # Nested archive inspection
            has_nested = False
            archive_contents: List[str] = []
            if is_archive and ext == ".zip":
                try:
                    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                        archive_contents = zf.namelist()
                        for member_name in archive_contents:
                            member_lower = member_name.lower()
                            if any(member_lower.endswith(arch_ext) for arch_ext in ARCHIVE_EXTENSIONS):
                                has_nested = True
                            if any(member_lower.endswith(exe_ext) for exe_ext in EXECUTABLE_EXTENSIONS):
                                # Also capture executables inside archives
                                pass
                except Exception:
                    # Broken or encrypted archive
                    pass

            attachments.append(
                AttachmentMetadata(
                    filename=clean_filename,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    md5=md5_hash,
                    sha256=sha256_hash,
                    is_macro_capable=is_macro,
                    has_double_extension=has_double,
                    is_archive=is_archive,
                    has_nested_archive=has_nested,
                    archive_contents=archive_contents,
                )
            )

        return attachments
