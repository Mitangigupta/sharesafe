# 🛡️ ShareSafe — Sovereign Privacy & Document Redaction Studio

> **Share documents without exposing your identity.** Real-time PII detection, QR Payload X-Ray inspection, face detection, true vector text destruction, AI Privacy Assistant, and cryptographic redaction audit certification — 100% on-device, zero cloud.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.1-emerald.svg)
![PyMuPDF](https://img.shields.io/badge/PyMuPDF-1.24%2B-red.svg)
![OpenCV](https://img.shields.io/badge/OpenCV-5.0-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Privacy](https://img.shields.io/badge/Privacy-100%25%20On--Device-teal.svg)

---

## 🌟 Overview

**ShareSafe** is an enterprise-grade privacy engineering web application built with Flask that identifies, assesses, and irreversibly redacts sensitive personal, financial, and infrastructure data from uploaded images (PNG, JPG, WEBP, BMP) and PDF documents before sharing.

### 🛡️ Core Pipeline Workflow

$$\text{Upload} \longrightarrow \text{Deep Scan} \longrightarrow \text{Detect} \longrightarrow \text{Risk Assessment} \longrightarrow \text{AI Analysis} \longrightarrow \text{Select \& Redact} \longrightarrow \text{Before/After Preview} \longrightarrow \text{Download Safe Copy}$$

**Real-time progress:** Each scan stage streams live step updates to the browser via Server-Sent Events (SSE), so users always know exactly what ShareSafe is doing.

---

## 🔬 Flaw Analysis & ShareSafe Mitigations

| Identified Flaw in Standard Redactors | Real-World Security Risk | ShareSafe Architectural Mitigation |
|---|---|---|
| **1. Pseudo-Redaction in PDFs** | Overlaying a black rectangle on a PDF often leaves the vector text stream intact. Attackers can copy the redacted text or run `pdftotext`. | **True Rasterization & Stream Destruction**: ShareSafe physically removes text objects via `page.apply_redactions()` and flattens pages into high-DPI rasterized layers. Text recovery is mathematically impossible. |
| **2. The "Hidden QR" Blindspot** | Users black out printed Aadhaar numbers but leave the QR code unredacted. Anyone with a smartphone can scan the QR and retrieve full identity data. | **Deep QR Payload X-Ray**: Decodes QR barcodes via OpenCV, analyzes payloads (UPI, vCard, Wi-Fi, UIDAI XML), and defaults them for redaction. |
| **3. Regex False Positives & Alert Fatigue** | Naive regex mistakes random 10-digit order numbers for Aadhaar UIDs or credit card numbers. | **Algorithmic Checksum Validation**: Implements the **Verhoeff algorithm** for Aadhaar and **Luhn mod-10** for payment cards, eliminating false-positive noise. |
| **4. Metadata Privacy Leakage** | Redacting pixels leaves EXIF camera serials, author history, and GPS coordinates intact. | **Zero-Leak Metadata Stripper**: Strips all EXIF tags, GPS metadata, and PDF `/Info` / `/XMP` dictionaries during export. |
| **5. Visual PII (Faces) Missed** | Most redactors only detect text — human faces in documents (ID cards, medical files) are ignored entirely. | **Face Detection via OpenCV Haar Cascades**: Detects faces as HIGH-priority biometric findings under DPDP Act §3 and GDPR Art.9, recommending blur redaction. |
| **6. No Regulatory Context** | Redactors flag data but don't tell users which law requires protection. | **Compliance Tag Mapping**: Each finding shows a colour-coded chip — DPDP §3, GDPR Art.4/9, PCI-DSS R3, ISO 27001 — directly on the finding card. |

---

## 💡 Project Novelty

### 🛡️ "QR Payload Threat X-Ray & Cryptographic Redaction Certificate"

1. **QR Payload Threat Inspector**: Rather than treating a QR code merely as a visual square, ShareSafe decodes the payload and identifies whether it is an **e-Aadhaar Identity QR**, **UPI payment string** (`upi://pay?pa=...`), **vCard Contact Card**, or **Wi-Fi password**. Provides a dedicated "Threat Inspector" dialog showing exactly what confidential data is leaking.

2. **Cryptographic Redaction Proof**: Generates an exportable PDF and JSON compliance receipt containing SHA-256 pre/post-redaction hashes, list of purged PII classes, timestamp, and compliance badges (India DPDP Act, GDPR Article 17, HIPAA Safe Harbor). A shareable link gives evaluators instant access to the audit proof.

3. **AI Privacy Assistant**: Generates context-aware natural language summaries of why a document is sensitive, broken down by severity (Critical/High/Medium/Low) with expandable explanations for every finding.

---

## 🚀 Features

### 🔍 Sensitive Information Detection Engine

- 🇮🇳 **Indian Aadhaar UID** — Verhoeff checksum validated (12-digit + masked VID formats)
- 🇮🇳 **Indian PAN** — Entity-type aware (`[A-Z]{5}[0-9]{4}[A-Z]`)
- 🇮🇳 **Indian Passport** — Format `[A-PR-WY][0-9]{7}` with document context
- 🇮🇳 **IFSC Code + Bank Account** — `[A-Z]{4}0[A-Z0-9]{6}` routing + labeled account numbers
- 💳 **Credit / Debit Cards** — Visa, Mastercard, Amex, RuPay via Luhn Mod-10
- 📞 **Phone Numbers** — International E.164 and Indian mobile `+91`
- ✉️ **Email Addresses** — RFC 5322 compatible
- 🇺🇸 **Social Security Numbers (SSN)** — US 9-digit format
- 🌐 **IPv4 Addresses** — Internal subnets and public gateways
- 🏦 **IBAN** — International bank account identifiers with country routing
- 🔑 **Cloud & Developer Secrets** — AWS Access Keys (`AKIA…`), JWT tokens, GitHub tokens, OpenAI keys
- 👤 **Human Faces** — OpenCV Haar cascade biometric detection (DPDP §3 / GDPR Art.9)
- 📲 **QR Codes** — Deep payload inspection (UPI, vCard, Wi-Fi, UIDAI)
- 📋 **Names, Addresses, DOB** — Context-labelled personal data fields

### 🎨 5 Redaction Styles

| Style | Effect |
|-------|--------|
| ⬛ Solid Blackout | Classic opaque privacy block |
| 💧 Gaussian Blur | Soft aesthetic blur ($k=35$) |
| 🟩 Mosaic Pixelate | Censored pixelated downsample |
| 🏷️ Redacted Stamp | Dark badge labeled `[REDACTED: TYPE]` |
| ⬜ Clean Whiteout | Background-matching white box |

### 🤖 AI Privacy Assistant

- Compact **AI Privacy Overview** card with 2–3 sentence summary
- Live severity chips (Critical / High / Medium / Low) from real scan data
- Expandable full analysis per finding
- **Compliance tags** on every card: DPDP §3, GDPR Art.4/9, PCI-DSS R3, ISO 27001
- **Confidence score bars** (colour-coded: green/amber/grey)
- Context-aware risk scoring (Academic / Professional / Private / Public)

### 🛠️ Workbench

- **Real-time SSE scan progress** — Live step labels fill a progress bar during scanning
- **Animated risk score dial** — Conic-gradient radial fills to actual threat score on load
- **Dark mode toggle** — Full theme switch persisted in `localStorage`
- **Undo stack** — Undo last manual redaction or accepted finding
- **One-click "Redact All High Risk"** — Selects and exports all Critical+High findings in one click
- **Manual draw redaction** — Crosshair tool for custom regions (handwriting, logos, stamps)
- **Before/After split slider** — Draggable comparison of original vs. sanitised
- **Interactive canvas** — Click bounding boxes to toggle individual redactions
- **Keyboard shortcuts** — `?` opens shortcut cheat sheet; `Ctrl+Shift+R` redacts all high risk

### 🔒 Privacy & Security

- **100% on-device** — Zero cloud upload; all files processed in ephemeral RAM
- **SHA-256 audit certificate** — Tamper-evident PDF + JSON export
- **Shareable cert link** — Generate a public read-only URL for the audit proof
- **Automatic session cleanup** — Files purged after 30 minutes; 1-click "Purge Now" button
- **Magic-byte file validation** — Rejects malformed files before processing
- **Latent metadata forensics** — Full EXIF/GPS/author tag inventory

### 🌐 Browser Extension

- Chromium Manifest V3 extension (Chrome / Edge)
- Real-time PII scanning of webpage text selections
- Pre-upload shield for Gmail and WhatsApp Web attachments
- 1-click in-situ redaction of form drafts

---

## 📁 Project Structure

```
sharesafe/
├── app.py                    # Flask application + SSE progress endpoint
├── config.py                 # Configuration & allowed file types
├── core/
│   ├── scanner.py            # Multi-modal scan orchestrator (PDF + image + face)
│   ├── regex_detector.py     # 30+ PII regex patterns with Verhoeff/Luhn validation
│   ├── ocr_engine.py         # Dual OCR (Tesseract / Windows WinRT)
│   ├── qr_detector.py        # OpenCV QR decode + payload threat analysis
│   ├── risk_assessor.py      # Context-weighted risk scoring engine
│   ├── privacy_assistant.py  # AI recommendation generator
│   ├── redactor.py           # 5-style canvas redaction pipeline
│   ├── metadata_cleaner.py   # EXIF/GPS/PDF metadata forensics + stripping
│   ├── certificate_gen.py    # SHA-256 cryptographic audit certificate
│   └── cleanup.py            # Ephemeral session management
├── static/
│   ├── css/style.css         # Design system (ivory + coral + dark mode)
│   └── js/
│       ├── app.js            # Upload flow + SSE EventSource client
│       └── canvas_editor.js  # Interactive bounding box + draw canvas
├── templates/
│   ├── base.html             # Base layout with SVG favicon
│   ├── index.html            # Hero upload + sharing context selector
│   ├── workbench.html        # Full privacy review workspace
│   └── ...                   # Informational pages
├── samples/                  # 3 synthetic demo documents
└── README.md
```

---

## ⚙️ Installation

```bash
git clone https://github.com/Mitangigupta/sharesafe.git
cd sharesafe
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` in your browser.

**Optional OCR (for scanned images):** Install [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) or use Windows (WinRT OCR is auto-detected on Windows 10+).

---

## 🎯 Keyboard Shortcuts (Workbench)

| Shortcut | Action |
|----------|--------|
| `?` | Show keyboard shortcut cheat sheet |
| `Ctrl+Shift+R` | Redact All High Risk (select + export) |
| `Ctrl+Shift+A` | Accept all recommendations |
| `Ctrl+Z` | Undo last manual redaction |
| `Escape` | Close any open modal / drawer |

---

## 🗺️ Compliance Coverage

| Detection Type | Regulation | Article / Section |
|---|---|---|
| Aadhaar, PAN, Passport | DPDP Act 2023 | §3 — Personal Data |
| Credit Card, Bank Account | PCI-DSS | Requirement 3 |
| Email, Phone, DOB | GDPR | Art. 4(1), Art. 9 |
| IBAN | PSD2 | Art. 4 |
| AWS Key, JWT, SSH Key | ISO 27001 | A.9.2 — Access Control |
| Human Face | GDPR + DPDP | Art. 9 / §3 — Biometric |
| Medical Data | HIPAA | §164.514 — PHI |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ for the academic privacy engineering evaluation. All demo documents contain 100% synthetic fictional data.*
