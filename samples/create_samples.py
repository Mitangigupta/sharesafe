"""
ShareSafe Synthetic Sample Generator
Generates realistic fictional documents for 1-click testing:
1. aadhaar_pan_sample.png (Synthetic Indian ID card with Aadhaar, PAN, Phone, and UPI QR code)
2. medical_invoice.pdf (Healthcare bill with patient email, phone, credit card number, and address)
3. server_config.png (DevOps config with IPv4 addresses, AWS secrets, and JWT tokens)
"""

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image, ImageDraw, ImageFont
import qrcode
import pymupdf
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from core.regex_detector import generate_verhoeff_check_digit

SAMPLE_DIR = Path(__file__).resolve().parent

def generate_samples():
    print("Generating synthetic sample files in:", SAMPLE_DIR)
    _create_aadhaar_pan_sample()
    _create_medical_invoice_pdf()
    _create_server_config_sample()
    print("All sample files generated successfully!")


def _create_aadhaar_pan_sample():
    """
    Creates a realistic synthetic Indian Identity Card image with:
    - Fictional Name: Aarav Sharma
    - Valid Aadhaar with Verhoeff check: 9823 4512 8735
    - Valid PAN: ABCPS1234K
    - Phone: +91 98765 43210
    - Embedded real UPI QR code
    """
    width, height = 900, 560
    # Background: clean gradient-style ID card
    card = Image.new("RGB", (width, height), (248, 250, 252))
    draw = ImageDraw.Draw(card)

    # Outer border & header banner
    draw.rectangle([10, 10, width - 10, height - 10], outline=(203, 213, 225), width=2)
    # Header tricolor accent
    draw.rectangle([12, 12, width - 12, 22], fill=(255, 153, 51))    # Saffron
    draw.rectangle([12, 22, width - 12, 32], fill=(255, 255, 255))   # White
    draw.rectangle([12, 32, width - 12, 42], fill=(19, 136, 8))      # Green

    # Government of India / Unique Identification Authority header banner
    draw.rectangle([12, 42, width - 12, 105], fill=(30, 41, 59))
    draw.text((30, 55), "GOVERNMENT OF INDIA - PROVISIONAL CITIZEN ID", fill=(255, 255, 255))
    draw.text((30, 80), "UNIQUE IDENTIFICATION & INCOME TAX DEPARTMENT", fill=(148, 163, 184))

    # Photo Box Placeholder
    photo_x, photo_y = 45, 135
    draw.rectangle([photo_x, photo_y, photo_x + 160, photo_y + 200], fill=(226, 232, 240), outline=(148, 163, 184), width=2)
    draw.text((photo_x + 35, photo_y + 90), "[ CITIZEN PHOTO ]", fill=(100, 116, 139))

    # Compute valid Verhoeff Aadhaar: base 98234512873 + check digit
    cd = generate_verhoeff_check_digit("98234512873")
    aadhaar_num = f"9823 4512 873{cd}"

    # Personal Details
    text_x = 240
    draw.text((text_x, 135), "Full Name:", fill=(100, 116, 139))
    draw.text((text_x + 120, 135), "Aarav Sharma", fill=(15, 23, 42))

    draw.text((text_x, 175), "Date of Birth:", fill=(100, 116, 139))
    draw.text((text_x + 120, 175), "14/08/1992 (Male)", fill=(15, 23, 42))

    draw.text((text_x, 215), "Mobile Phone:", fill=(100, 116, 139))
    draw.text((text_x + 120, 215), "+91 98765 43210", fill=(15, 23, 42))

    draw.text((text_x, 255), "Permanent PAN:", fill=(100, 116, 139))
    draw.text((text_x + 120, 255), "ABCPS1234K", fill=(15, 23, 42))

    draw.text((text_x, 295), "Father's Name:", fill=(100, 116, 139))
    draw.text((text_x + 120, 295), "Rajesh Sharma", fill=(15, 23, 42))

    # Aadhaar UID Banner
    draw.rectangle([30, 365, width - 30, 445], fill=(238, 242, 255), outline=(99, 102, 241), width=2)
    draw.text((50, 380), "Aadhaar Number / आधार क्रमांक :", fill=(79, 70, 229))
    draw.text((50, 405), aadhaar_num, fill=(17, 24, 39))

    # Generate real QR Code containing UPI payment string
    qr_payload = "upi://pay?pa=aarav.sharma@okhdfcbank&pn=Aarav%20Sharma&am=1500.00&cu=INR"
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(qr_payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_img = qr_img.resize((150, 150))
    
    # Paste QR Code on right side of card
    qr_x = width - 190
    qr_y = 140
    card.paste(qr_img, (qr_x, qr_y))
    draw.text((qr_x - 5, qr_y + 155), "Scan for Verification", fill=(100, 116, 139))

    # Security Watermark / Bottom Footer
    draw.rectangle([12, height - 70, width - 12, height - 12], fill=(241, 245, 249))
    draw.text((30, height - 55), "SECURE DEMOGRAPHIC DATA RECORD - FOR OFFICIAL USE ONLY", fill=(100, 116, 139))
    draw.text((30, height - 35), "Verification Portal: https://eaadhaar.uidai.gov.in/verify | Helpline: 1947", fill=(148, 163, 184))

    out_file = SAMPLE_DIR / "aadhaar_pan_sample.png"
    card.save(out_file, "PNG")
    print("Created:", out_file)


def _create_medical_invoice_pdf():
    """
    Creates a digital medical billing invoice PDF with:
    - Patient: Johnathan Doe
    - Email: john.doe.care@example-health.org
    - Phone: +1 (555) 839-2041
    - Credit Card: 4532 0150 1234 5678 (valid Luhn format)
    - Address: 742 Evergreen Terrace, Springfield
    """
    out_file = SAMPLE_DIR / "medical_invoice.pdf"
    doc = SimpleDocTemplate(
        str(out_file),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "MedTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a")
    )
    sub_style = ParagraphStyle(
        "MedSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#64748b")
    )
    section_style = ParagraphStyle(
        "MedSec",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        "MedBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )

    story = []

    # Clinic Header
    header_data = [
        [
            Paragraph("🏥 <b>METROPOLITAN HEALTHCARE & RADIOLOGY CLINIC</b>", title_style),
            Paragraph("<b>INVOICE #:</b> INV-2026-9821<br/><b>Date:</b> March 15, 2026", sub_style)
        ]
    ]
    t_head = Table(header_data, colWidths=[360, 180])
    t_head.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
    ]))
    story.append(t_head)
    story.append(Spacer(1, 14))

    # Patient Details Table
    story.append(Paragraph("Patient Billing & Contact Profile", section_style))
    patient_data = [
        [Paragraph("<b>Patient Name:</b>", body_style), Paragraph("Johnathan Doe", body_style),
         Paragraph("<b>Date of Birth:</b>", body_style), Paragraph("1985-06-22", body_style)],
        [Paragraph("<b>Email:</b>", body_style), Paragraph("john.doe.care@example-health.org", body_style),
         Paragraph("<b>Phone:</b>", body_style), Paragraph("+1 (555) 839-2041", body_style)],
        [Paragraph("<b>Billing Address:</b>", body_style), Paragraph("742 Evergreen Terrace, Springfield, IL 62704", body_style),
         Paragraph("<b>Insurance ID:</b>", body_style), Paragraph("MED-99410-X", body_style)]
    ]
    t_pat = Table(patient_data, colWidths=[90, 180, 90, 180])
    t_pat.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_pat)
    story.append(Spacer(1, 14))

    # Medical Items Table
    story.append(Paragraph("Itemized Diagnostic & Radiology Services", section_style))
    items_data = [
        [Paragraph("<b>Code</b>", body_style), Paragraph("<b>Service Description</b>", body_style), Paragraph("<b>Qty</b>", body_style), Paragraph("<b>Amount (USD)</b>", body_style)],
        [Paragraph("RAD-70450", body_style), Paragraph("CT Scan Head / Brain with Contrast", body_style), Paragraph("1", body_style), Paragraph("$1,250.00", body_style)],
        [Paragraph("LAB-80053", body_style), Paragraph("Comprehensive Metabolic Panel (Blood)", body_style), Paragraph("1", body_style), Paragraph("$185.00", body_style)],
        [Paragraph("PHY-99214", body_style), Paragraph("Specialist Consultation & Follow-up", body_style), Paragraph("1", body_style), Paragraph("$240.00", body_style)],
        [Paragraph("", body_style), Paragraph("<b>Total Hospital Balance</b>", body_style), Paragraph("", body_style), Paragraph("<b>$1,675.00</b>", body_style)]
    ]
    t_items = Table(items_data, colWidths=[80, 270, 50, 140])
    t_items.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(t_items)
    story.append(Spacer(1, 14))

    # Payment Card Section
    # Valid Luhn Visa test number: 4532 0150 1234 5678 -> let's compute valid check digit
    base_card = "453201501234567"
    # Luhn check calculation for 16th digit
    total = 0
    for i, c in enumerate(reversed(base_card)):
        d = int(c)
        if i % 2 == 0:  # 15th digit reversed is index 0 -> doubled
            d *= 2
            if d > 9: d -= 9
        total += d
    check_digit = (10 - (total % 10)) % 10
    valid_card = f"{base_card[:4]} {base_card[4:8]} {base_card[8:12]} {base_card[12:]}{check_digit}"

    story.append(Paragraph("Electronic Payment Settlement Information", section_style))
    pay_data = [
        [Paragraph("<b>Payment Method:</b>", body_style), Paragraph("Visa Debit/Credit Card (Primary)", body_style)],
        [Paragraph("<b>Cardholder Name:</b>", body_style), Paragraph("JOHNATHAN DOE", body_style)],
        [Paragraph("<b>Credit Card Number:</b>", body_style), Paragraph(valid_card, body_style)],
        [Paragraph("<b>Card Expiration / CVV:</b>", body_style), Paragraph("11/2028 | 482", body_style)],
        [Paragraph("<b>Transaction Status:</b>", body_style), Paragraph("<font color='#10b981'><b>AUTHORIZED - BATCH #82719</b></font>", body_style)]
    ]
    t_pay = Table(pay_data, colWidths=[160, 380])
    t_pay.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#94a3b8")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_pay)
    story.append(Spacer(1, 14))

    # Privacy notice
    story.append(Paragraph(
        "<i>CONFIDENTIAL MEDICAL RECORD: This document contains protected health information (PHI) and cardholder data. Unauthorized copying or distribution is strictly prohibited under HIPAA and PCI-DSS rules.</i>",
        sub_style
    ))

    doc.build(story)
    print("Created:", out_file)


def _create_server_config_sample():
    """
    Creates a server config / DevOps log image with:
    - Internal and external IPv4 addresses
    - AWS Access Key
    - JWT auth token
    - Bearer authorization secret
    """
    width, height = 960, 560
    img = Image.new("RGB", (width, height), (15, 23, 42))  # Slate 900 dark background
    draw = ImageDraw.Draw(img)

    # Window title bar
    draw.rectangle([0, 0, width, 36], fill=(30, 41, 59))
    # Window buttons
    draw.ellipse([14, 12, 24, 22], fill=(239, 68, 68))   # Red
    draw.ellipse([32, 12, 42, 22], fill=(245, 158, 11))  # Yellow
    draw.ellipse([50, 12, 60, 22], fill=(16, 185, 129))  # Green
    draw.text((75, 11), "bash: root@production-cluster-node-01:/etc/security/app.env", fill=(148, 163, 184))

    # Terminal Content
    lines = [
        "# PRODUCTION ENVIRONMENT DEVOPS CONFIGURATION - CONFIDENTIAL",
        "# DO NOT EXPOSE TO PUBLIC REPOSITORIES OR CLIENT LOGS",
        "",
        "NODE_ENV=production",
        "CLUSTER_REGION=us-east-1",
        "INTERNAL_GATEWAY_IP=192.168.1.105",
        "EXTERNAL_EGRESS_IP=203.0.113.45",
        "",
        "# AWS Cloud Services Authentication",
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "AWS_DEFAULT_REGION=us-east-1",
        "",
        "# Production API Security & Session Tokens",
        "AUTH_BEARER_TOKEN=Bearer sec_live_98a7b6c5d4e3f2109876543210",
        "",
        "# Service Account Master JWT (HS256)",
        "MASTER_JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "",
        "ADMIN_ALERT_EMAIL=ops-security@infra-vault.internal",
        "EMERGENCY_ONCALL_PHONE=+1-555-019-2834"
    ]

    y = 52
    for line in lines:
        if line.startswith("#"):
            fill_color = (100, 116, 139)  # Slate comments
        elif line.startswith("AWS_") or line.startswith("AUTH_") or line.startswith("MASTER_"):
            fill_color = (248, 113, 113)  # Red alert for keys & secrets
        elif "IP=" in line:
            fill_color = (251, 191, 36)   # Amber for IPs
        elif line.startswith("ADMIN_") or line.startswith("EMERGENCY_"):
            fill_color = (96, 165, 250)   # Blue for contacts
        else:
            fill_color = (226, 232, 240)  # Light white/grey

        draw.text((25, y), line, fill=fill_color)
        y += 24

    out_file = SAMPLE_DIR / "server_config.png"
    img.save(out_file, "PNG")
    print("Created:", out_file)


if __name__ == "__main__":
    generate_samples()
