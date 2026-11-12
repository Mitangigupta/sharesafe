# 🛡️ ShareSafe Chrome Extension (Manifest V3)

> Defensive privacy scanner that detects sensitive personally identifiable information (PII), financial credentials, API tokens, and identity numbers in webpage selections, drafts, messaging, and automated file uploads before sharing.

---

## 🌟 Features Implemented

### Phase 1: Core Selection & Algorithmic Detection
- **Selection Context Menu**: Highlight text on any webpage, right-click, and choose **"Scan with ShareSafe"**.
- **Unified Backend Engine**: Uses the ShareSafe Python core directly (`/api/scan-text` and `/api/inspect-file`) — zero duplicated detection logic.
- **Checksum-Validated Detection**:
  - 🇮🇳 **Indian Aadhaar UID**: 12-digit format verified with the **Verhoeff checksum algorithm** (Mod-10 Dihedral group $D_5$).
  - 🇮🇳 **Indian PAN**: Alphanumeric `[A-Z]{5}[0-9]{4}[A-Z]{1}` with entity code validation.
  - 💳 **Credit / Debit Cards**: Visa, Mastercard, Amex, RuPay verified with **Luhn Mod-10 algorithm**.
  - 📞 **Phone Numbers**: International standard (E.164) and Indian mobile (`+91`).
  - ✉️ **Email Addresses**: RFC 5322 compatible regex.
  - 🇺🇸 **US Social Security Numbers (SSN)**: 9-digit format (`XXX-XX-XXXX`).
  - 🌐 **IPv4 Addresses**: Internal subnets and public internet gateways.
  - 🔑 **Cloud Secrets**: AWS Access Keys (`AKIA...`), JWT tokens (`eyJ...`), secret tokens (`ghp_`, `sk-`, etc.).
- **Context-Aware Risk Assessment**:
  - Select between **Academic** ($1.0\times$), **Professional** ($1.1\times$), **Private** ($0.85\times$), and **Public** ($1.3\times$) modes.
  - Composite risk score ($0$ to $100$) and status badge (`CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Privacy Assistant Guidance**: Prioritized actionable advice (`HIGH_PRIORITY`, `REVIEW`).
- **1-Click Sanitized Text Copy**: Automatically generates a safe copy with sensitive values masked.
- **Quick Input Tab**: Paste or type any snippet directly into the popup to scan without opening a webpage.

### Phase 2: Platform Adapters & In-Situ Compose Inspection
- ✉️ **Gmail In-Situ Compose Adapter (`gmail-adapter.js`)**:
  - Automatically detects when browsing active Gmail sessions (`https://mail.google.com/*`).
  - Discovers active email composition containers (dock windows, inline replies, and full-screen compose).
  - 1-Click **"Scan Compose Draft"** extracts draft text on-demand without any keylogging.
  - **In-Place Draft Replacement**: Replaces cleartext PII with masked tokens directly in Gmail with 1 click.
  - **Pre-Send Warning Banner**: Injects an alert banner above the compose region when critical PII is detected.
- 💬 **WhatsApp Web In-Situ Adapter (`whatsapp-adapter.js`)**:
  - Automatically identifies active WhatsApp Web tabs (`https://web.whatsapp.com/*`).
  - Scopes to the active message input field without reading chat history or threads.
  - 1-Click **"Scan Compose Draft"** checks message text before pressing Enter.
  - **In-Place Message Redaction**: Automatically injects sanitized text into the compose box.
  - **Floating Warning Chip**: Floats a defensive reminder if high-risk credentials are typed.

### Phase 3: Automated Pre-Upload File Screening & Defensive Shield
- 🛡️ **Automated Pre-Upload File Shield (`file-shield.js`)**:
  - Automatically intercepts document attachments, drag-and-drop actions, and clipboard pastes in WhatsApp Web and Gmail.
  - Dispatches PDFs and images (`.pdf`, `.png`, `.jpg`, `.jpeg`, `.webp`, `.bmp`) to the local ShareSafe core (`/api/inspect-file`) in milliseconds.
  - **If Clean**: Upload proceeds automatically without friction.
  - **If Sensitive (Medium, High, or Critical Risk)**:
    - Halts the upload and displays the in-page **ShareSafe Pre-Upload Shield Modal**.
    - Lists detected credentials (Aadhaar, PAN, Credit Cards, QR payloads).
    - **🛑 Cancel Upload**: Aborts upload and protects user identity.
    - **✏️ Redact in ShareSafe Studio**: Opens `http://127.0.0.1:5000/workbench/<session_id>` with the file pre-scanned and ready for 1-click vector redaction!
    - **⚠️ Send Unredacted (Override)**: Releases pause lock if the user explicitly authorizes transmission.

---

## 🚀 Installation & Loading in Chrome / Edge

### Step 1: Ensure ShareSafe Backend is Running
In your terminal, start the ShareSafe server:
```bash
cd C:\Users\mitan\.gemini\antigravity\scratch\sharesafe
python app.py
```
*(Server runs at `http://127.0.0.1:5000`)*

### Step 2: Load Unpacked Extension in Chrome / Edge
1. Open Google Chrome and navigate to `chrome://extensions/` (or `edge://extensions/` in Edge).
2. Toggle **Developer mode** on (top-right corner).
3. If already loaded: Click the **🔄 Reload** icon on the ShareSafe card.
4. If loading for the first time: Click **Load unpacked** and select `sharesafe-extension`.
5. Pin the shield icon to your toolbar.

---

## 🔬 Testing & Verification

### 1. Phase 1 Verification (Context Menu & Quick Input)
- Highlight test text: *"Contact resident at +91 98765 43210 or Aadhaar 2345 6789 0123 with PAN ABCDE1234F"*.
- Right-click $\to$ choose **"Scan with ShareSafe"** $\to$ check findings in popup.

### 2. Phase 2 Verification (In-Situ Draft Scan & Redaction)
- In WhatsApp Web or Gmail, type a draft message containing credit cards or phone numbers.
- Open popup $\to$ click **"Scan Compose Draft"** $\to$ switch to **Sanitized Text** $\to$ click **"Replace in Draft"**.

### 3. Phase 3 Verification (Automated File Upload Shield)
1. In WhatsApp Web, open any chat.
2. Click the attach paperclip $\to$ select a document, or drag and drop a sample PDF (e.g., `samples/medical_invoice.pdf` or `samples/aadhaar_pan_sample.png`) into the chat.
3. Observe ShareSafe immediately pause the upload and display the in-page **Pre-Upload Shield Modal** detailing the detected Aadhaar/Visa credentials.
4. Click **"Cancel Upload"** to verify that the sensitive file was blocked from sending, or click **"Redact in ShareSafe Studio"** to open the Workbench!

---

## 🔒 Security & Privacy Guarantees

- **Zero Surveillance**: Content scripts do NOT monitor keystrokes, hook keyboard events, or log typing.
- **Scoped Extraction**: Scans only the currently focused draft text or intercepted file attachment when triggered.
- **Strictly Ephemeral**: Findings reside exclusively in `chrome.storage.session`, which is automatically wiped when the browser closes.
- **Unified Engine**: Powered entirely by the sovereign, on-device Python engine without third-party cloud analytics.
