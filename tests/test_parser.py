"""Unit tests for Module 1 Parser."""
from email.message import EmailMessage
import io
import zipfile

from phishtriage.parser import EmlParser


def test_parser_basic_text_email():
    msg = EmailMessage()
    msg["From"] = "Alice Boss <alice@corporate.com>"
    msg["To"] = "Bob Worker <bob@corporate.com>"
    msg["Subject"] = "Quarterly Sync"
    msg["Date"] = "Mon, 20 Oct 2026 10:00:00 +0000"
    msg.set_content("Hi Bob,\nPlease review our dashboard at https://corporate.com/reports.\nThanks!")

    raw_bytes = msg.as_bytes()
    parser = EmlParser()
    parsed = parser.parse_bytes(raw_bytes)

    assert parsed.subject == "Quarterly Sync"
    assert parsed.from_name == "Alice Boss"
    assert parsed.from_address == "alice@corporate.com"
    assert "https://corporate.com/reports" in [u.url for u in parsed.urls]
    assert len(parsed.attachments) == 0


def test_parser_html_url_mismatch_and_shortener():
    msg = EmailMessage()
    msg["From"] = "Security Team <security@bank-notice.top>"
    msg["To"] = "victim@corporate.com"
    msg["Subject"] = "Urgent: Reset Your Password"
    html_content = """
    <html>
      <body>
        <p>Please update your credentials immediately.</p>
        <a href="http://bit.ly/fake-login">https://mybank.com/login</a>
      </body>
    </html>
    """
    msg.add_alternative(html_content, subtype="html")

    raw_bytes = msg.as_bytes()
    parser = EmlParser()
    parsed = parser.parse_bytes(raw_bytes)

    assert len(parsed.urls) >= 1
    mismatch_url = next(u for u in parsed.urls if "bit.ly" in u.url)
    assert mismatch_url.is_shortener is True
    assert mismatch_url.mismatch_with_text is True
    assert mismatch_url.display_text == "https://mybank.com/login"


def test_parser_attachment_analysis():
    msg = EmailMessage()
    msg["From"] = "Vendor <invoicing@supplier.com>"
    msg["To"] = "finance@corporate.com"
    msg["Subject"] = "Overdue Invoice"
    msg.set_content("See attached invoice.")

    # 1. Macro-enabled office attachment
    msg.add_attachment(b"fake macro payload", maintype="application", subtype="vnd.ms-excel.sheet.macroEnabled.12", filename="Invoice_March.xlsm")

    # 2. Double extension attachment
    msg.add_attachment(b"MZ executable header", maintype="application", subtype="octet-stream", filename="statement.pdf.exe")

    # 3. Zip containing another zip (archive-in-archive)
    inner_zip_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_zip_buffer, "w") as zf_inner:
        zf_inner.writestr("malware.vbs", "WScript.Echo 'evil'")
    
    outer_zip_buffer = io.BytesIO()
    with zipfile.ZipFile(outer_zip_buffer, "w") as zf_outer:
        zf_outer.writestr("nested.zip", inner_zip_buffer.getvalue())

    msg.add_attachment(outer_zip_buffer.getvalue(), maintype="application", subtype="zip", filename="docs.zip")

    parser = EmlParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    assert len(parsed.attachments) == 3

    xlsm_att = next(a for a in parsed.attachments if a.filename == "Invoice_March.xlsm")
    assert xlsm_att.is_macro_capable is True
    assert xlsm_att.sha256 != ""

    double_att = next(a for a in parsed.attachments if a.filename == "statement.pdf.exe")
    assert double_att.has_double_extension is True

    zip_att = next(a for a in parsed.attachments if a.filename == "docs.zip")
    assert zip_att.is_archive is True
    assert zip_att.has_nested_archive is True
    assert "nested.zip" in zip_att.archive_contents
