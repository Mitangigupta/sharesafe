# 🛡️ ShareSafe — Defensive PII & QR Privacy Redaction Suite

> **Share documents without exposing your identity.** Real-time PII detection, QR Payload X-Ray inspection, true vector text destruction, and cryptographic redaction audit certification.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.1-emerald.svg)
![PyMuPDF](https://img.shields.io/badge/PyMuPDF-1.24%2B-red.svg)
![OpenCV](https://img.shields.io/badge/OpenCV-5.0-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Privacy](https://img.shields.io/badge/Privacy-100%25%20On--Device-teal.svg)

---

## 🌟 Overview

**ShareSafe** is an enterprise-grade cybersecurity web application built with Flask that identifies, assesses, and irreversibly redacts sensitive personal, financial, and infrastructure data from uploaded images (PNG, JPG, WEBP, BMP) and PDF documents before sharing.

### 🛡️ Core Pipeline Workflow:
$$\text{Upload} \longrightarrow \text{Deep Scan} \longrightarrow \text{Detect} \longrightarrow \text{Risk Assessment} \longrightarrow \text{Select \& Redact} \longrightarrow \text{Before/After Preview} \longrightarrow \text{Download Safe Copy}$$

---

## 🔬 Flaw Analysis & ShareSafe Mitigations

| Identified Flaw in Standard Redactors | Real-World Security Risk | ShareSafe Architectural Mitigation |
|---|---|---|
| **1. Pseudo-Redaction in PDFs** | Overlaying a black rectangle on a PDF often leaves the vector text stream intact. Attackers can simply highlight and copy the redacted text or run `pdftotext` to extract all confidential records. | **True Rasterization & Stream Destruction**: ShareSafe physically removes text objects from the PDF content stream (`page.apply_redactions()`) and flattens pages into high-DPI rasterized layers. Text recovery is mathematically impossible (0 extractable characters). |
| **2. The "Hidden QR" Blindspot** | Users black out printed Aadhaar numbers or invoice totals, but leave the QR code unredacted. Anyone with a smartphone can scan the QR and instantly retrieve the resident's full name, biometric hash, Aadhaar UID, or payment routing. | **Deep QR Payload Inspection (X-Ray)**: ShareSafe decodes QR barcodes via OpenCV, analyzes their payloads (UPI strings, vCards, Wi-Fi credentials, UIDAI XML), warns the user of the data leakage, and defaults it to being redacted. |
| **3. Regex False Positives & Alert Fatigue** | Naive regex patterns mistake random 10-digit order numbers or 12-digit barcodes for Indian Aadhaar or credit card numbers. | **Algorithmic Checksum Validation**: Implemented the **Verhoeff algorithm** for Indian Aadhaar validation and the **Luhn mod-10 algorithm** for Credit/Debit cards (Visa, Mastercard, Amex, RuPay), filtering out random numeric noise. |
| **4. Metadata Privacy Leakage** | Redacting pixels leaves EXIF camera serials, author history, editing software, and GPS coordinates intact. | **Zero-Leak Metadata Stripper**: ShareSafe strips all EXIF tags, GPS metadata, and PDF `/Info` / `/XMP` dictionaries during the export pipeline. |
| **5. Host Tesseract Dependency** | If Tesseract is not installed on the host OS, standard OCR apps crash abruptly on startup. | **Dual-Engine Architecture**: Digital PDFs are extracted with sub-millisecond precision via PyMuPDF native vector engine with zero binary dependencies. For images, automatic path discovery + runtime configuration modal + demo heuristics ensure the app never crashes. |

---

## 💡 Project Novelty

### 🛡️ "QR Payload Threat X-Ray & Cryptographic Redaction Certificate"
1. **QR Payload Threat Inspector**:
   - Rather than treating a QR code merely as a visual square, ShareSafe decodes the payload and identifies whether it is an **e-Aadhaar Identity QR**, **UPI payment string** (`upi://pay?pa=...`), **vCard Contact Card**, or **Wi-Fi password**.
   - Provides a dedicated "Threat Inspector" dialog showing users what confidential data is leaking through the QR code and why it must be redacted before sharing.
2. **Cryptographic Redaction Proof (Tamper-Evident Audit Certificate)**:
   - Generates an exportable PDF and JSON compliance receipt containing SHA-256 pre-redaction and post-redaction file hashes, list of purged PII classes, timestamp, and a compliance badge (aligned with India DPDP Act, GDPR Article 17, and HIPAA Safe Harbor), without revealing raw sensitive data.

---

## 🚀 Features

- **Sensitive Information Detectors**:
  - 🇮🇳 **Indian Aadhaar UID**: 12-digit format verified with the **Verhoeff checksum algorithm**.
  - 🇮🇳 **Indian PAN**: Alphanumeric `[A-Z]{5}[0-9]{4}[A-Z]{1}` with individual/corporate entity validation.
  - 💳 **Credit / Debit Cards**: Visa, Mastercard, American Express, RuPay verified with **Luhn Mod-10 algorithm**.
  - 📞 **Phone Numbers**: International standard (E.164) and Indian mobile numbers (`+91`).
  - ✉️ **Email Addresses**: RFC 5322 compatible regex.
  - 🇺🇸 **Social Security Numbers (SSN)**: US 9-digit format (`XXX-XX-XXXX`).
  - 🌐 **IPv4 Addresses**: Internal subnets and public internet gateways.
  - 🔑 **Cloud & Developer Secrets**: AWS Access Keys (`AKIA...`), JSON Web Tokens (JWT), and generic bearer tokens.
- **5 Redaction Styles**:
  - `⬛ Solid Blackout`: Classic opaque privacy block.
  - `💧 Gaussian Blur`: Soft aesthetic blur ($k=35$).
  - `🟩 Mosaic Pixelate`: Censored pixelated downsample.
  - `🏷️ Redacted Stamp`: Dark obsidian badge labeled `[REDACTED: AADHAAR]`.
  - `⬜ Clean Whiteout`: Background-matching white box.
- **Manual Redaction Crosshair Tool**:
  - Draw custom redaction rectangles over handwritten notes, logos, stamps, or faces.
- **Interactive Before / After Split Slider**:
  - Draggable central divider revealing original document on left and sanitized document on right.
- **1-Click Preloaded Demo Files**:
  - `aadhaar_pan_sample.png`: Indian Identity Card with Aadhaar, PAN, and UPI QR.
  - `medical_invoice.pdf`: Healthcare bill with Visa Card, SSN, and Email.
  - `server_config.png`: DevOps terminal with IPs, AWS Keys, and JWT tokens.
- **Automated Memory Cleanup & Privacy Sandboxing**:
  - Session files are stored in isolated directories and auto-purged after 30 minutes.
  - 1-click **"Purge Session Now"** button for immediate file destruction.

---

## 📁 Project Structure

```
sharesafe/
├── app.py                     # Flask application entry point, routing, error handlers
├── config.py                  # App configuration, upload limits, allowed formats, TTL
├── requirements.txt           # Production dependencies
├── .env.example               # Environment variables template
├── README.md                  # Comprehensive project documentation
├── core/
│   ├── __init__.py
│   ├── scanner.py             # Multi-modal PDF, OCR & QR scanner coordinator
│   ├── ocr_engine.py          # PyTesseract integration, path discovery & fallback
│   ├── regex_detector.py      # PII Regex rules + Luhn & Verhoeff checksum validators
│   ├── qr_detector.py         # OpenCV QR detector & deep payload threat analyzer
│   ├── risk_assessor.py       # Risk scoring engine (Low, Medium, High, Critical)
│   ├── redactor.py            # Image & PDF redaction engine with true flattening
│   ├── metadata_cleaner.py    # Strips EXIF, GPS, XMP, PDF /Info metadata
│   ├── certificate_gen.py     # Generates PDF & JSON cryptographic audit report
│   └── cleanup.py             # Session sandboxing & automated TTL cleanup routine
├── samples/
│   ├── generate_samples.py    # Generator script for realistic synthetic demo files
│   ├── aadhaar_pan_sample.png # Synthetic ID card with PAN, Aadhaar, Phone & QR
│   ├── medical_invoice.pdf    # Healthcare bill with Credit Card, Email, Address
│   └── server_config.png      # Config file with IP addresses, API Keys, Tokens
├── static/
│   ├── css/
│   │   └── style.css          # Privacy/Cybersecurity dark glassmorphic styling
│   └── js/
│       ├── app.js             # Upload handlers, scanner state, API client
│       └── canvas_editor.js   # Interactive bounding boxes, manual drawing & split slider
├── templates/
│   ├── base.html              # Layout shell, navigation, privacy disclaimer banner
│   ├── index.html             # Hero upload zone, sample picker, feature highlights
│   └── workbench.html         # Interactive scanning & redaction workbench
└── tests/
    ├── test_detector.py       # Unit tests for Verhoeff, Luhn, PAN, Phone, and QR
    ├── test_redactor.py       # Unit tests for image/PDF redaction and certificate
    ├── test_workflow.py       # Integration tests for full Flask upload/redact pipeline
    └── test_e2e.py            # End-to-end scanner and flattening verification
```

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- Python 3.10+ (Python 3.11, 3.12, 3.13 supported)
- Optional: Tesseract OCR (Only needed for scanning scanned raster photos; digital PDFs extract 100% natively via PyMuPDF).

### 2. Clone & Install Dependencies
```bash
cd C:\Users\mitan\.gemini\antigravity\scratch\sharesafe
pip install -r requirements.txt
```

### 3. (Optional) Install Tesseract OCR for Scanned Photos
- **Windows (Winget)**:
  ```powershell
  winget install UB-Mannheim.TesseractOCR
  ```
- **Linux (Ubuntu/Debian)**:
  ```bash
  sudo apt-get install tesseract-ocr
  ```
- **macOS (Homebrew)**:
  ```bash
  brew install tesseract
  ```
*Note: You can also specify your `tesseract.exe` path in the web UI via the "OCR Engine" button.*

---

## 🏃 Running ShareSafe

Start the Flask development server:
```bash
python app.py
```

Then open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Running Automated Tests

Run the full test suite:
```bash
python -m unittest discover -s tests
```

Expected output:
```
Ran 12 tests in 1.032s
OK
```

---

## 🔒 Security & Privacy Guarantee

- **Zero Cloud Leakage**: ShareSafe executes all scanning, OCR, QR decoding, and redactions locally in your machine's memory and local disk.
- **Non-Recoverable Flattening**: Sanitized PDFs do not contain invisible text layers or recoverable fonts.
- **Ephemeral Storage**: All temporary session files are wiped from disk automatically or on-demand.
