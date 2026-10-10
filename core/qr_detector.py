import re
import urllib.parse
from typing import List, Dict, Any, Optional
import cv2
import numpy as np

class QRDetector:
    """Detects QR codes, extracts bounding boxes, and performs deep payload threat inspection."""

    def __init__(self):
        self.detector = cv2.QRCodeDetector()

    def detect(self, image_np: np.ndarray) -> List[Dict[str, Any]]:
        """Scans a numpy image (BGR or Grayscale) for QR codes and analyzes their payloads."""
        if image_np is None or image_np.size == 0:
            return []

        if len(image_np.shape) == 3 and image_np.shape[2] == 4:
            # Convert RGBA to BGR
            image_np = cv2.cvtColor(image_np, cv2.COLOR_RGBA2BGR)
        elif len(image_np.shape) == 2:
            # Grayscale to BGR
            image_np = cv2.cvtColor(image_np, cv2.COLOR_GRAY2BGR)

        results = []
        found_data = []

        # Multi QR detection attempt
        try:
            retval, decoded_info, points, _ = self.detector.detectAndDecodeMulti(image_np)
            if retval and points is not None and len(points) > 0:
                for text, pts in zip(decoded_info, points):
                    if pts is not None and len(pts) >= 4:
                        found_data.append((text.strip() if text else "", pts))
        except Exception:
            pass

        # Fallback to single QR detection if multi didn't return any
        if not found_data:
            try:
                text, points, _ = self.detector.detectAndDecode(image_np)
                if points is not None and len(points) > 0:
                    found_data.append((text.strip() if text else "", points[0]))
            except Exception:
                pass

        # Process each detected QR code
        for idx, (payload, pts) in enumerate(found_data):
            # Calculate axis-aligned bounding box from points
            pts_array = np.array(pts, dtype=np.float32).reshape(-1, 2)
            x_min = float(np.min(pts_array[:, 0]))
            y_min = float(np.min(pts_array[:, 1]))
            x_max = float(np.max(pts_array[:, 0]))
            y_max = float(np.max(pts_array[:, 1]))

            width = max(1.0, x_max - x_min)
            height = max(1.0, y_max - y_min)

            # Analyze payload
            threat_analysis = self.analyze_payload(payload)

            results.append({
                'type': 'qr_code',
                'label': threat_analysis['title'],
                'value': payload if payload else "[Unreadable / Encrypted QR Code]",
                'masked': threat_analysis['preview'],
                'category': 'Digital Barcode / QR Payload',
                'risk': threat_analysis['risk'],
                'bbox': [round(x_min, 1), round(y_min, 1), round(width, 1), round(height, 1)],
                'polygon': pts_array.tolist(),
                'details': threat_analysis['description'],
                'payload_type': threat_analysis['payload_type'],
                'extracted_fields': threat_analysis.get('fields', {})
            })

        return results

    def analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Deep threat analysis of QR payload to reveal hidden PII and financial vectors."""
        if not payload:
            return {
                'title': 'QR Code (Unread/Scrambled)',
                'preview': '[Binary or Damaged QR]',
                'risk': 'MEDIUM',
                'payload_type': 'unknown',
                'description': 'QR code detected, but payload could not be decoded. May contain binary data or proprietary encoding.'
            }

        # 1. UPI Payment Payload (e.g. upi://pay?pa=recipient@okaxis&pn=John&am=1000)
        if payload.startswith('upi://') or 'upi://pay' in payload:
            fields = {}
            try:
                parsed = urllib.parse.urlparse(payload)
                query_params = urllib.parse.parse_qs(parsed.query)
                for k, v in query_params.items():
                    fields[k] = v[0] if v else ""
            except Exception:
                pass
                
            pa = fields.get('pa', 'Unknown VPA')
            pn = fields.get('pn', 'Unknown Payee')
            am = fields.get('am', '')
            
            return {
                'title': 'UPI Payment QR Code',
                'preview': f"Payee: {pn} ({pa})" + (f" | Amt: INR {am}" if am else ""),
                'risk': 'HIGH',
                'payload_type': 'upi',
                'fields': fields,
                'description': f"CRITICAL FINANCIAL LEAK: Encodes direct UPI payment routing address ({pa}) and recipient name ({pn}). Scanning transfers funds or resolves payee banking identity."
            }

        # 2. Aadhaar Secure QR / UIDAI XML Data
        if '<PrintLetterBarcodeData' in payload or 'uidai' in payload.lower() or (payload.isdigit() and len(payload) > 50):
            # UIDAI QR code
            fields = {}
            for match in re.finditer(r'([a-zA-Z_]+)="([^"]*)"', payload):
                fields[match.group(1)] = match.group(2)

            name = fields.get('name', 'Resident')
            uid = fields.get('uid', 'Aadhaar Holder')
            yob = fields.get('yob', fields.get('dob', ''))

            return {
                'title': 'UIDAI Aadhaar Identity QR',
                'preview': f"Resident: {name} | UID: {uid} | DOB: {yob}",
                'risk': 'CRITICAL',
                'payload_type': 'aadhaar_qr',
                'fields': fields,
                'description': "CRITICAL PRIVACY EXPOSURE: This QR code contains unredacted Indian demographic data (full name, DOB, gender, address). Blacking out printed text while leaving this QR allows any scanner to extract full identity!"
            }

        # 3. vCard / MeCard Contact Payload
        if 'BEGIN:VCARD' in payload.upper() or payload.upper().startswith('MECARD:'):
            fields = {}
            fn_m = re.search(r'(?:FN|N):([^\r\n;]+)', payload, re.IGNORECASE)
            tel_m = re.search(r'TEL[^:]*:([^\r\n;]+)', payload, re.IGNORECASE)
            email_m = re.search(r'EMAIL[^:]*:([^\r\n;]+)', payload, re.IGNORECASE)
            adr_m = re.search(r'ADR[^:]*:([^\r\n]+)', payload, re.IGNORECASE)

            if fn_m: fields['Name'] = fn_m.group(1).strip()
            if tel_m: fields['Phone'] = tel_m.group(1).strip()
            if email_m: fields['Email'] = email_m.group(1).strip()
            if adr_m: fields['Address'] = adr_m.group(1).strip()

            preview = f"{fields.get('Name', 'Contact')} | {fields.get('Phone', '')} | {fields.get('Email', '')}"
            return {
                'title': 'Personal vCard Contact QR',
                'preview': preview.strip(' |'),
                'risk': 'HIGH',
                'payload_type': 'vcard',
                'fields': fields,
                'description': "Direct Contact Leak: Encodes personal phone number, email address, and physical location into a scannable address card."
            }

        # 4. Wi-Fi Access Point Credentials (WIFI:S:MySSID;T:WPA;P:MyPassword;;)
        if payload.startswith('WIFI:'):
            ssid_m = re.search(r'S:([^;]+);', payload)
            pass_m = re.search(r'P:([^;]+);', payload)
            ssid = ssid_m.group(1) if ssid_m else "Unknown Network"
            has_pass = bool(pass_m and pass_m.group(1))

            return {
                'title': 'Wi-Fi Network Credentials QR',
                'preview': f"Network: {ssid} (Password: {'Protected' if has_pass else 'None'})",
                'risk': 'HIGH' if has_pass else 'MEDIUM',
                'payload_type': 'wifi',
                'fields': {'SSID': ssid, 'HasPassword': str(has_pass)},
                'description': "Network Security Breach: Contains network authentication parameters. Allows anyone with the image to connect to the private network."
            }

        # 5. URLs / Web Hyperlinks
        if payload.startswith(('http://', 'https://')):
            return {
                'title': 'Web URL Link QR',
                'preview': payload[:50] + ('...' if len(payload) > 50 else ''),
                'risk': 'LOW',
                'payload_type': 'url',
                'fields': {'URL': payload},
                'description': f"Directs to web destination: {payload}"
            }

        # 6. Generic Text Payload
        return {
            'title': 'Text / Data QR Code',
            'preview': payload[:45] + ('...' if len(payload) > 45 else ''),
            'risk': 'MEDIUM',
            'payload_type': 'text',
            'fields': {'Raw': payload},
            'description': "Custom data payload embedded in QR barcode."
        }
