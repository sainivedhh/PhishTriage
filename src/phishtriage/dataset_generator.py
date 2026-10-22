"""Synthetic dataset generator creating 100+ labeled .eml email fixtures.
Includes:
- Benign corporate emails (updates, syncs, lunch invites)
- Benign newsletters (marketing, product digests, legitimate links)
- Benign lookalikes (brand mentions, authorized domains)
- Phishing (credential harvesting, href mismatches, shorteners, punycode/lookalike domains, double-extension attachments)
- BEC (VIP impersonation, confidential wire transfer, gift card urgency, fake invoices)
"""
from __future__ import annotations

from email.message import EmailMessage
import json
from pathlib import Path
from typing import Dict


def build_synthetic_dataset(output_dir: str = "data/synthetic_dataset") -> Dict[str, str]:
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    labels: Dict[str, str] = {}

    # Category 1: 30 Benign corporate emails
    for i in range(1, 31):
        filename = f"benign_corp_{i:03d}.eml"
        msg = EmailMessage()
        msg["From"] = f"colleague{i}@corporate.com"
        msg["To"] = "employee@corporate.com"
        msg["Subject"] = f"Project Status Update #{i}"
        msg["Date"] = "Wed, 21 Oct 2026 14:00:00 +0000"
        msg["Authentication-Results"] = "mx.corporate.com; dkim=pass header.i=@corporate.com; spf=pass; dmarc=pass"
        msg["Received"] = "from mail.corporate.com by mx.corporate.com with ESMTPS; Wed, 21 Oct 2026 14:00:00 +0000"
        msg.set_content(
            f"Hi team,\n\nHere is the weekly update for Sprint {i}. Everything is on schedule.\nPlease check the wiki at https://corporate.com/wiki/sprint{i} if you need details.\n\nBest,\nColleague {i}"
        )
        (out_path / filename).write_bytes(msg.as_bytes())
        labels[filename] = "benign"

    # Category 2: 20 Benign Newsletters and Marketing
    for i in range(1, 21):
        filename = f"benign_newsletter_{i:03d}.eml"
        msg = EmailMessage()
        msg["From"] = f"Tech Weekly Digest <newsletter@tech-digest-{i}.com>"
        msg["To"] = "subscriber@corporate.com"
        msg["Subject"] = f"Top Engineering Articles of the Week (Issue #{i})"
        msg["Date"] = "Tue, 20 Oct 2026 09:30:00 +0000"
        msg["Authentication-Results"] = f"mx.corporate.com; dkim=pass header.i=@tech-digest-{i}.com; spf=pass; dmarc=pass"
        msg["Received"] = f"from mail.tech-digest-{i}.com by mx.corporate.com with ESMTPS; Tue, 20 Oct 2026 09:30:00 +0000"
        html_body = f"""
        <html>
          <body>
            <h2>Tech Weekly #{i}</h2>
            <p>Welcome to this week's issue. Catch up on the latest trends in software architecture.</p>
            <p>Read full post: <a href="https://tech-digest-{i}.com/issue-{i}">https://tech-digest-{i}.com/issue-{i}</a></p>
            <p><small>To unsubscribe, click <a href="https://tech-digest-{i}.com/unsub">here</a>.</small></p>
          </body>
        </html>
        """
        msg.add_alternative(html_body, subtype="html")
        (out_path / filename).write_bytes(msg.as_bytes())
        labels[filename] = "benign"

    # Category 3: 10 Benign Edge Cases (External vendors, legitimate lookalike words)
    for i in range(1, 11):
        filename = f"benign_edge_{i:03d}.eml"
        msg = EmailMessage()
        msg["From"] = f"support@authorized-partner-{i}.org"
        msg["To"] = "procurement@corporate.com"
        msg["Subject"] = f"Partner Meeting Request #{i}"
        msg["Date"] = "Wed, 21 Oct 2026 11:00:00 +0000"
        msg["Authentication-Results"] = f"mx.corporate.com; dkim=pass header.i=@authorized-partner-{i}.org; spf=pass; dmarc=pass"
        msg.set_content(
            f"Hello,\n\nWe would like to schedule our quarterly partner touchpoint. Looking forward to speaking with the corporate leadership team.\n\nRegards,\nPartner {i}"
        )
        (out_path / filename).write_bytes(msg.as_bytes())
        labels[filename] = "benign"

    # Category 4: 25 Phishing emails (Credential harvest, shorteners, mismatches, lookalikes, double ext)
    for i in range(1, 26):
        filename = f"phishing_credential_{i:03d}.eml"
        msg = EmailMessage()
        msg["Date"] = "Wed, 21 Oct 2026 16:00:00 +0000"

        if i <= 8:
            # Lookalike domain + DMARC fail + Credential harvest
            msg["From"] = "IT Support <support@paypa1.com>" if i % 2 == 0 else "Corporate Security <admin@corporat3.com>"
            msg["To"] = "victim@corporate.com"
            msg["Subject"] = f"Urgent: Reset Your Password Immediately (#{i})"
            msg["Authentication-Results"] = "mx.corporate.com; spf=fail; dmarc=fail; dkim=none"
            html_body = f"""
            <html>
              <body>
                <h3>Security Alert</h3>
                <p>Your account has been locked. Click here to login and verify your identity within 24 hours.</p>
                <a href="http://192.168.1.10{i}/login">https://corporate.com/login</a>
              </body>
            </html>
            """
            msg.add_alternative(html_body, subtype="html")
        elif i <= 16:
            # Shortener + Suspicious TLD + href mismatch
            msg["From"] = f"Account Notice <security@notice-center-{i}.top>"
            msg["To"] = "victim@corporate.com"
            msg["Subject"] = f"Critical Alert: Action Required on Your Account #{i}"
            msg["Authentication-Results"] = "mx.corporate.com; spf=softfail; dkim=none; dmarc=fail"
            html_body = f"""
            <html>
              <body>
                <p>Final notice: your account will be suspended.</p>
                <a href="https://bit.ly/fake-alert-{i}">https://security-verify.corporate.com</a>
              </body>
            </html>
            """
            msg.add_alternative(html_body, subtype="html")
        elif i <= 21:
            # Double extension attachment + Punycode lookalike
            msg["From"] = "Billing Department <invoice@xn--pple-43d.com>"
            msg["To"] = "victim@corporate.com"
            msg["Subject"] = f"Overdue Payment Invoice #{i}"
            msg["Authentication-Results"] = "mx.corporate.com; spf=fail; dkim=none; dmarc=fail"
            msg.set_content("Please review the overdue invoice attached.")
            msg.add_attachment(b"MZ executable header", maintype="application", subtype="octet-stream", filename=f"invoice_{i}.pdf.exe")
        else:
            # Macro-enabled document or zip archive evasion
            msg["From"] = f"Vendor Shipping <tracking@untrusted-relay-{i}.xyz>"
            msg["To"] = "victim@corporate.com"
            msg["Subject"] = f"Order Confirmation & Tracking Document #{i}"
            msg["Authentication-Results"] = "mx.corporate.com; spf=fail; dkim=none; dmarc=fail"
            msg.set_content("See the attached shipping confirmation macro spreadsheet.")
            msg.add_attachment(b"fake macro excel sheet", maintype="application", subtype="vnd.ms-excel.sheet.macroEnabled.12", filename=f"shipping_manifest_{i}.xlsm")

        (out_path / filename).write_bytes(msg.as_bytes())
        labels[filename] = "malicious"

    # Category 5: 20 BEC / Executive Impersonation Emails
    for i in range(1, 21):
        filename = f"bec_executive_{i:03d}.eml"
        msg = EmailMessage()
        msg["Date"] = "Wed, 21 Oct 2026 17:00:00 +0000"
        msg["From"] = f"Jane Smith <ceo-private-mobile-{i}@gmail.com>"
        msg["To"] = "finance@corporate.com"
        msg["Reply-To"] = f"Offshore Wire Dept <wire-desk-{i}@scam-transfers.net>"
        msg["Subject"] = f"Confidential Wire Transfer Request #{i}"
        msg["Authentication-Results"] = "mx.corporate.com; dkim=pass header.i=@gmail.com; spf=pass; dmarc=none"
        msg["Received"] = "from mail-qk1.google.com by mx.corporate.com with ESMTPS; Wed, 21 Oct 2026 17:00:00 +0000"
        msg.set_content(
            f"Hi finance,\n\nI am currently in an urgent board meeting and cannot take phone calls. "
            f"Please execute an urgent wire transfer for $45,{i}00 to our new acquisition partner. "
            f"Keep this transaction strictly confidential between us.\n\nJane Smith\nCEO"
        )
        (out_path / filename).write_bytes(msg.as_bytes())
        labels[filename] = "malicious"

    # Save labels JSON
    labels_file = out_path / "labels.json"
    with open(labels_file, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2)

    return labels


if __name__ == "__main__":
    generated = build_synthetic_dataset()
    print(f"Generated {len(generated)} labeled synthetic samples in data/synthetic_dataset")
