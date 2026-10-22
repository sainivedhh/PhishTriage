"""Attachment triage module: double extensions, macro-enabled files, archive inspection, and hash blocklists."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set
from pydantic import BaseModel

from phishtriage.models import AttachmentMetadata


class AttachmentFinding(BaseModel):
    filename: str
    sha256: str
    finding_type: str
    description: str
    severity: str  # critical, high, medium, low


class AttachmentTriager:
    """Evaluates attachment safety offline via static metadata, structures, and local hash blocklists."""

    def __init__(self, blocklist_file: Optional[str | Path] = None) -> None:
        self.blocklist_hashes: Set[str] = set()
        if blocklist_file:
            path = Path(blocklist_file)
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.blocklist_hashes.add(line.lower())

    def triage(self, attachments: List[AttachmentMetadata]) -> List[AttachmentFinding]:
        findings: List[AttachmentFinding] = []

        for att in attachments:
            # 1. Local Blocklist Match
            if att.sha256.lower() in self.blocklist_hashes:
                findings.append(
                    AttachmentFinding(
                        filename=att.filename,
                        sha256=att.sha256,
                        finding_type="known_malicious_hash",
                        description=f"Attachment '{att.filename}' matched known malware SHA-256 signature.",
                        severity="critical",
                    )
                )

            # 2. Double Extension Spoofing
            if att.has_double_extension:
                findings.append(
                    AttachmentFinding(
                        filename=att.filename,
                        sha256=att.sha256,
                        finding_type="double_extension",
                        description=f"Attachment '{att.filename}' disguises an executable behind a benign secondary extension.",
                        severity="critical",
                    )
                )

            # 3. Macro-capable Office Document
            if att.is_macro_capable:
                findings.append(
                    AttachmentFinding(
                        filename=att.filename,
                        sha256=att.sha256,
                        finding_type="macro_capable_document",
                        description=f"Attachment '{att.filename}' is a macro-enabled Office container capable of arbitrary code execution.",
                        severity="high",
                    )
                )

            # 4. Nested Archive / Archive-in-Archive
            if att.has_nested_archive:
                findings.append(
                    AttachmentFinding(
                        filename=att.filename,
                        sha256=att.sha256,
                        finding_type="nested_archive",
                        description=f"Attachment '{att.filename}' contains a nested archive (evasion technique). Contents: {att.archive_contents}",
                        severity="high",
                    )
                )

            # 5. Executable or Script inside archive
            if att.is_archive:
                for inner_file in att.archive_contents:
                    lower = inner_file.lower()
                    if lower.endswith((".exe", ".vbs", ".js", ".bat", ".scr", ".ps1", ".hta", ".cmd", ".iso")):
                        findings.append(
                            AttachmentFinding(
                                filename=att.filename,
                                sha256=att.sha256,
                                finding_type="executable_in_archive",
                                description=f"Archive '{att.filename}' packages executable or script payload '{inner_file}'.",
                                severity="critical",
                            )
                        )

        return findings
