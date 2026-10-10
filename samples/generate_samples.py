import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import qrcode
from PIL import Image, ImageDraw, ImageFont
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from core.regex_detector import generate_verhoeff_checksum, validate_luhn

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))

def create_sample_aadhaar_pan():
    """Generates a synthetic Indian Identity Card image with Aadhaar (Verhoeff), PAN, Phone, and UIDAI/UPI QR code."""
    out_path = os.path.join(SAMPLES_DIR, "aadhaar_pan_sample.png")
    w, h = 800, 520
    img = Image.new("RGB", (w, h), (248, 250, 252))
    draw = ImageDraw.Draw(img)

    # Outer card border with header
    draw.rectangle([(20, 20), (w - 20, h - 20)], fill=(255, 255, 255), outline=(203, 213, 225), width=2)
    # Header bar
    draw.rectangle([(20, 20), (w - 20, 85)], fill=(15, 23, 42))

    # Header text
    draw.text((40, 32), "GOVERNMENT OF INDIA / IDENTITY VERIFICATION MOCK", fill=(255, 255, 255))
    draw.text((40, 56), "ShareSafe Synthetic Test Document - Strictly Fictional Data", fill=(148, 163, 184))

    # Fictional Photo Box
    draw.rectangle([(50, 110), (190, 280)], fill=(226, 232, 240), outline=(148, 163, 184), width=1)
    draw.text((80, 185), "[ PHOTO ]", fill=(100, 116, 139))

    # Resident Details
    draw.text((220, 115), "Name / Resident:", fill=(100, 116, 139))
    draw.text((220, 135), "ROHAN SHARMA", fill=(15, 23, 42))

    draw.text((220, 170), "Date of Birth:", fill=(100, 116, 139))
    draw.text((220, 190), "14/08/1992", fill=(15, 23, 42))

    draw.text((380, 170), "Gender:", fill=(100, 116, 139))
    draw.text((380, 190), "MALE", fill=(15, 23, 42))

    draw.text((220, 225), "Phone (Mobile):", fill=(100, 116, 139))
    draw.text((220, 245), "+91 98765 43210", fill=(15, 23, 42))

    # PAN Number
    draw.text((220, 280), "Permanent Account Number (PAN):", fill=(100, 116, 139))
    draw.text((220, 300), "ABCDE1234F", fill=(185, 28, 28))

    # Verhoeff-valid synthetic Aadhaar number
    aadhaar_11 = "23456789012"
    valid_aadhaar_clean = generate_verhoeff_checksum(aadhaar_11)
    valid_aadhaar_formatted = f"{valid_aadhaar_clean[:4]} {valid_aadhaar_clean[4:8]} {valid_aadhaar_clean[8:]}"

    # Big Aadhaar Banner at bottom
    draw.rectangle([(40, 360), (w - 40, 440)], fill=(241, 245, 249), outline=(226, 232, 240), width=1)
    draw.text((60, 375), "AADHAAR NUMBER / UNIQUE IDENTIFICATION AUTHORITY OF INDIA", fill=(71, 85, 105))
    draw.text((60, 398), valid_aadhaar_formatted, fill=(15, 23, 42))

    draw.text((40, 465), "Disclaimer: All names, numbers, and identifiers are computer-generated synthetic artifacts.", fill=(148, 163, 184))

    # Generate Scannable QR Code containing UIDAI XML & UPI link payload
    qr_payload = f"upi://pay?pa=rohan.sharma@okaxis&pn=Rohan%20Sharma&am=500&cu=INR"
    qr = qrcode.QRCode(version=1, box_size=4, border=1)
    qr.add_data(qr_payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img = qr_img.resize((150, 150))

    img.paste(qr_img, (w - 200, 110))
    draw.text((w - 200, 268), "Scan UPI / UIDAI", fill=(100, 116, 139))

    img.save(out_path)
    print(f"Generated Aadhaar/PAN sample at {out_path}")
    return out_path

def create_sample_medical_pdf():
    """Generates a synthetic Healthcare Invoice PDF with Credit Card (Luhn), SSN, Email, and Phone."""
    out_path = os.path.join(SAMPLES_DIR, "medical_invoice.pdf")
    doc = SimpleDocTemplate(out_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    # Valid Luhn Card number: Visa
    visa_card = "4532 0156 7890 1239"
    assert validate_luhn(visa_card), "Test visa card must pass Luhn"

    elements = []
    
    # Header
    title_style = ParagraphStyle('MedTitle', fontName='Helvetica-Bold', fontSize=18, leading=22, textColor=colors.HexColor('#0f172a'))
    sub_style = ParagraphStyle('MedSub', fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor('#64748b'))
    body_style = ParagraphStyle('MedBody', fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor('#1e293b'))
    bold_style = ParagraphStyle('MedBold', fontName='Helvetica-Bold', fontSize=9, leading=13, textColor=colors.HexColor('#0f172a'))

    elements.append(Paragraph("METROPOLITAN GENERAL HOSPITAL & HEALTH CLINIC", title_style))
    elements.append(Paragraph("Patient Statement & Confidential Billing Invoice (FICTIONAL DEMO)", sub_style))
    elements.append(Spacer(1, 15))

    # Patient & Billing Info Table
    info_data = [
        [Paragraph("<b>Patient Name:</b> Alice Walker", body_style), Paragraph("<b>Invoice #:</b> INV-2026-9042", body_style)],
        [Paragraph("<b>Email:</b> alice.walker@medicare-demo.org", body_style), Paragraph("<b>Date:</b> 2026-09-12", body_style)],
        [Paragraph("<b>Phone:</b> +1 (555) 234-5678", body_style), Paragraph("<b>SSN:</b> 123-45-6789", body_style)],
        [Paragraph("<b>Attending Physician:</b> Dr. Sarah Jenkins, MD", body_style), Paragraph("<b>Department:</b> Cardiology Outpatient", body_style)],
    ]
    t_info = Table(info_data, colWidths=[270, 260])
    t_info.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_info)
    elements.append(Spacer(1, 15))

    # Itemized Services Table
    item_data = [
        [Paragraph("<b>Service Description</b>", bold_style), Paragraph("<b>Code</b>", bold_style), Paragraph("<b>Quantity</b>", bold_style), Paragraph("<b>Amount</b>", bold_style)],
        [Paragraph("Comprehensive Electrocardiogram (ECG)", body_style), Paragraph("CPT-93000", body_style), Paragraph("1", body_style), Paragraph("$250.00", body_style)],
        [Paragraph("Specialist Consultation & Evaluation", body_style), Paragraph("CPT-99214", body_style), Paragraph("1", body_style), Paragraph("$185.00", body_style)],
        [Paragraph("Comprehensive Metabolic Blood Panel", body_style), Paragraph("CPT-80053", body_style), Paragraph("1", body_style), Paragraph("$115.00", body_style)],
        [Paragraph("<b>Total Billed Amount:</b>", bold_style), Paragraph("", body_style), Paragraph("", body_style), Paragraph("<b>$550.00</b>", bold_style)],
    ]
    t_items = Table(item_data, colWidths=[240, 90, 80, 120])
    t_items.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#ffffff'), colors.HexColor('#f1f5f9')])
    ]))
    elements.append(t_items)
    elements.append(Spacer(1, 15))

    # Payment Record Table
    pay_data = [
        [Paragraph("<b>Payment Method:</b> Credit Card (Visa)", body_style)],
        [Paragraph(f"<b>Card Number on Record:</b> {visa_card}", body_style)],
        [Paragraph("<b>Card Expiration:</b> 08/29 &nbsp;&nbsp;&nbsp;&nbsp; <b>CVV/CVC:</b> [Stored Securely]", body_style)],
        [Paragraph("<b>Billing Address:</b> 742 Evergreen Terrace, Springfield, IL 62704", body_style)]
    ]
    t_pay = Table(pay_data, colWidths=[530])
    t_pay.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fffbeb')),  # Light amber
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#f59e0b')),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(t_pay)
    elements.append(Spacer(1, 15))

    # QR Code for Invoice Portal
    qr_tmp = os.path.join(SAMPLES_DIR, "_tmp_invoice_qr.png")
    qr = qrcode.QRCode(version=1, box_size=3, border=1)
    qr.add_data("https://medicare-demo.org/portal/pay?invoice=INV-2026-9042&patient=AliceWalker")
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(qr_tmp)

    bottom_data = [
        [RLImage(qr_tmp, width=80, height=80), 
         Paragraph("<b>Digital Payment Portal:</b><br/>Scan to access billing terminal.<br/><i>Notice: Contains patient identification and billing tokens.</i>", body_style)]
    ]
    t_bot = Table(bottom_data, colWidths=[90, 440])
    elements.append(t_bot)

    doc.build(elements)
    if os.path.exists(qr_tmp):
        os.remove(qr_tmp)

    print(f"Generated Medical Invoice sample at {out_path}")
    return out_path

def create_sample_server_config():
    """Generates a synthetic Server Configuration screenshot with IP addresses, AWS API keys, and JWT tokens."""
    out_path = os.path.join(SAMPLES_DIR, "server_config.png")
    w, h = 850, 520
    img = Image.new("RGB", (w, h), (15, 23, 42))  # Dark terminal aesthetic
    draw = ImageDraw.Draw(img)

    # Window title bar
    draw.rectangle([(0, 0), (w, 36)], fill=(30, 41, 59))
    # Red, yellow, green window dots
    draw.ellipse([(12, 12), (24, 24)], fill=(239, 68, 68))
    draw.ellipse([(32, 12), (44, 24)], fill=(245, 158, 11))
    draw.ellipse([(52, 12), (64, 24)], fill=(16, 185, 129))
    draw.text((80, 11), "bash - root@prod-gateway-01:~/.env (PRODUCTION SECRETS)", fill=(148, 163, 184))

    # Code lines
    y = 55
    lines = [
        ("# PRODUCTION DEPLOYMENT SECRETS - DO NOT COMMIT TO PUBLIC REPO", (100, 116, 139)),
        ("NODE_ENV=production", (148, 163, 184)),
        ("CLUSTER_NAME=aws-us-east-cluster-main", (148, 163, 184)),
        ("", (148, 163, 184)),
        ("# Network Topology", (100, 116, 139)),
        ("INTERNAL_HOST_IP=192.168.1.105", (248, 250, 252)),
        ("PUBLIC_GATEWAY_IP=203.0.113.45", (248, 250, 252)),
        ("SECURITY_OFFICER_EMAIL=devops-sec@cloudcorp-demo.io", (248, 250, 252)),
        ("", (148, 163, 184)),
        ("# Cloud Provider Access", (100, 116, 139)),
        ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", (239, 68, 68)),
        ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", (239, 68, 68)),
        ("", (148, 163, 184)),
        ("# Service Mesh JWT Auth Token", (100, 116, 139)),
        ("JWT_AUTH_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", (245, 158, 11)),
    ]

    for line_text, color in lines:
        draw.text((25, y), line_text, fill=color)
        y += 24

    # Embedded QR code containing Wi-Fi access credentials
    qr = qrcode.QRCode(version=1, box_size=3, border=1)
    qr.add_data("WIFI:S:CorpDev_Secure_5G;T:WPA;P:SuperSecretPass2026!;;")
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img = qr_img.resize((120, 120))

    img.paste(qr_img, (w - 150, h - 150))
    draw.text((w - 160, h - 25), "Wi-Fi Access QR", fill=(148, 163, 184))

    img.save(out_path)
    print(f"Generated Server Config sample at {out_path}")
    return out_path

if __name__ == '__main__':
    create_sample_aadhaar_pan()
    create_sample_medical_pdf()
    create_sample_server_config()
    print("All sample files generated successfully!")
