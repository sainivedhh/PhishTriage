"""Unit tests for Module 5 Attachment Triager."""
from phishtriage.attachment_triage import AttachmentTriager
from phishtriage.models import AttachmentMetadata


def test_attachment_triage_double_ext_and_blocklist(tmp_path):
    blocklist = tmp_path / "blocklist.txt"
    sample_sha = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    blocklist.write_text(f"{sample_sha}\n")

    triager = AttachmentTriager(blocklist_file=blocklist)

    attachments = [
        AttachmentMetadata(
            filename="document.pdf.exe",
            content_type="application/octet-stream",
            size_bytes=1024,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256=sample_sha,
            is_macro_capable=False,
            has_double_extension=True,
            is_archive=False,
            has_nested_archive=False,
        )
    ]

    findings = triager.triage(attachments)
    types = [f.finding_type for f in findings]
    assert "known_malicious_hash" in types
    assert "double_extension" in types


def test_attachment_triage_macros_and_archive_evasion():
    triager = AttachmentTriager()
    attachments = [
        AttachmentMetadata(
            filename="invoice.xlsm",
            content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
            size_bytes=2048,
            md5="aaa",
            sha256="bbb",
            is_macro_capable=True,
            has_double_extension=False,
            is_archive=False,
            has_nested_archive=False,
        ),
        AttachmentMetadata(
            filename="payload.zip",
            content_type="application/zip",
            size_bytes=4096,
            md5="ccc",
            sha256="ddd",
            is_macro_capable=False,
            has_double_extension=False,
            is_archive=True,
            has_nested_archive=True,
            archive_contents=["sub.zip", "run.bat"],
        ),
    ]

    findings = triager.triage(attachments)
    types = [f.finding_type for f in findings]
    assert "macro_capable_document" in types
    assert "nested_archive" in types
    assert "executable_in_archive" in types
