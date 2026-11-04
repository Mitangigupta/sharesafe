# 🛡️ ShareSafe Chrome Extension (Manifest V3)

> Defensive privacy scanner that detects sensitive personally identifiable information (PII), financial credentials, API tokens, and identity numbers in webpage selections, drafts, and messaging before sharing.

---

## 🌟 Features Implemented

### Phase 1: Core Selection & Algorithmic Detection
- **Selection Context Menu**: Highlight text on any webpage, right-click, and choose **"Scan with ShareSafe"**.
- **Unified Backend Engine**: Uses the ShareSafe Python core directly (`/api/scan-text`) — zero duplicated detection logic.
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
3. Click **Load unpacked** (top-left button).
4. Select the `sharesafe-extension` folder:
   ```
   C:\Users\mitan\.gemini\antigravity\scratch\sharesafe\sharesafe-extension
   ```
5. The extension **"ShareSafe — PII & Privacy Guard"** (v1.1.0) is now loaded! Pin it to your browser toolbar.

---

## 🔬 Testing & Verification

### 1. Phase 1 Verification (Context Menu & Quick Input)
1. Select a sample test string on any page:
   > *"Contact resident at +91 98765 43210 or Aadhaar 2345 6789 0123 with PAN ABCDE1234F"*
2. Right-click and choose **"Scan with ShareSafe"**.
3. Open the extension popup from your toolbar.
4. Review findings: Aadhaar UID (Verhoeff-validated), PAN Card, and Indian Phone Number will appear with CRITICAL risk, masked text, and assistant guidance.

### 2. Phase 2 Verification (Gmail & WhatsApp Web)
1. **Gmail Test**:
   - Open [Gmail](https://mail.google.com) and click **Compose**.
   - Type in the body: *"Please process invoice with card 4111 1111 1111 1111 and secret AKIAIOSFODNN7EXAMPLE"*.
   - Click the ShareSafe extension icon. A green badge indicates **"Gmail Detected"**.
   - Click **"Scan Compose Draft"**.
   - Review findings in popup.
   - Switch to **Sanitized Text** tab and click **"Replace in Draft"** $\to$ the email body is automatically sanitized!
2. **WhatsApp Web Test**:
   - Open [WhatsApp Web](https://web.whatsapp.com) and click into any chat compose field.
   - Type a phone number or Aadhaar.
   - Click the extension icon $\to$ click **"Scan Compose Draft"**.
   - View instant risk scoring and click **"Replace in Draft"** to mask the sensitive credentials before sending.

---

## 🔒 Security & Privacy Guarantees

- **Zero Surveillance**: Content scripts do NOT monitor keystrokes, hook keyboard events, or log typing.
- **Scoped Extraction**: Scans only the currently focused draft text when explicitly commanded by the user.
- **Strictly Ephemeral**: Findings reside exclusively in `chrome.storage.session`, which is automatically wiped when the browser closes.
- **Unified Engine**: Powered entirely by the sovereign, on-device Python engine without third-party cloud analytics.
