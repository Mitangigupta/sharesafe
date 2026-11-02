# 🛡️ ShareSafe Chrome Extension (Manifest V3)

> Defensive privacy scanner that detects sensitive personally identifiable information (PII), financial credentials, API tokens, and identity numbers in webpage selections, drafts, and messages before sharing.

---

## 🌟 Features (Phase 1 Implemented)

- **Selection Context Menu**: Highlight text on any webpage, right-click, and choose **"Scan with ShareSafe"**.
- **Unified Backend Engine**: Uses the ShareSafe Python core directly — zero duplicated detection logic.
- **Checksum-Validated Detection**:
  - 🇮🇳 **Indian Aadhaar UID**: 12-digit format verified with the **Verhoeff checksum algorithm**.
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
- **Privacy Assistant Guidance**: Prioritized actionable advice (`HIGH_PRIORITY`, `REVIEW`, `INFORMATIONAL`).
- **1-Click Sanitized Text Copy**: Automatically generates a safe copy with sensitive values masked.
- **Quick Input Tab**: Paste or type any snippet directly into the popup to scan without opening a webpage.

---

## 🚀 Installation & Loading in Chrome

### Step 1: Ensure ShareSafe Backend is Running
In your terminal, start the ShareSafe server:
```bash
cd C:\Users\mitan\.gemini\antigravity\scratch\sharesafe
python app.py
```
*(Server runs at `http://127.0.0.1:5000`)*

### Step 2: Load Unpacked Extension in Chrome
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** on (top-right corner).
3. Click **Load unpacked** (top-left button).
4. Select the `sharesafe-extension` folder:
   ```
   C:\Users\mitan\.gemini\antigravity\scratch\sharesafe\sharesafe-extension
   ```
5. The extension **"ShareSafe — PII & Privacy Guard"** is now loaded! Pin it to your Chrome toolbar.

---

## 🔬 Testing Phase 1

1. **Context Menu Test**:
   - Open any webpage (e.g. Wikipedia or a news article).
   - Select a sample test string, for example:
     > *"Contact resident at +91 98765 43210 or Aadhaar 2345 6789 0123 with PAN ABCDE1234F"*
   - Right-click and choose **"Scan with ShareSafe"**.
   - Open the ShareSafe extension popup from your toolbar.
   - Review findings: Aadhaar UID (Verhoeff-validated), PAN Card, and Indian Phone Number will appear with CRITICAL risk, masked text, and assistant guidance.
2. **Quick Input Test**:
   - Click the extension icon to open the popup.
   - Switch to the **Quick Input** tab.
   - Paste: `AKIAIOSFODNN7EXAMPLE and card 4111 1111 1111 1111`.
   - Click **"Scan with ShareSafe"**.
   - Review the immediate detection of the AWS IAM key and Luhn-validated Visa card.
   - Switch to **Sanitized Text** and click **"Copy Text"** to get the safe version.

---

## 🔒 Security & Privacy Guarantees

- **Minimal Permissions**: Uses only `contextMenus`, `storage`, and `activeTab`. Does NOT request `<all_urls>`.
- **Zero Surveillance**: Content scripts do NOT monitor keystrokes, log inputs, or scan background browsing.
- **Scoped Data Transmission**: Sends only the text the user explicitly chose to scan.
- **Ephemeral Findings**: Cached exclusively in `chrome.storage.session`, which is automatically wiped when the browser closes.
