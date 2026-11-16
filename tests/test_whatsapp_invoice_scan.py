import unittest
import os
import io
import json
from app import app
from core.scanner import DocumentScanner
from core.redactor import DocumentRedactor

class TestWhatsAppInvoiceAttachmentScanning(unittest.TestCase):
    def setUp(self):
        self.scanner = DocumentScanner()
        self.client = app.test_client()
        self.invoice_pdf = os.path.join(os.path.dirname(__file__), '..', 'samples', 'medical_invoice.pdf')
        self.invoice_150dpi = os.path.join(os.path.dirname(__file__), '..', 'samples', 'medical_invoice_150dpi.png')
        self.invoice_img = self.invoice_150dpi if os.path.exists(self.invoice_150dpi) else os.path.join(os.path.dirname(__file__), '..', 'uploads', 'ab2039c19d8e', 'attach_ad5c0742.png')
        self.samples_dir = os.path.join(os.path.dirname(__file__), '..', 'samples')

    def test_image_attachment_sensitive_categories_detection(self):
        """Verify that uploaded image attachment detects all required sensitive categories."""
        if not os.path.exists(self.invoice_img):
            self.skipTest("Hospital invoice image not found.")

        result = self.scanner.scan_file(self.invoice_img, self.samples_dir)
        detections = result['detections']
        self.assertGreater(len(detections), 0)

        types_found = {d['type']: d for d in detections}
        labels_found = {d['label']: d for d in detections}

        # Verify each of the required categories:
        # 1. Patient names
        names = [d for d in detections if d.get('type') == 'name' or 'Name' in d.get('label', '')]
        self.assertGreater(len(names), 0, "Patient/Physician names must be detected")
        name_values = [d['value'] for d in names]
        self.assertTrue(any('Alice Walker' in n for n in name_values), f"Expected 'Alice Walker' in names: {name_values}")
        for nd in names:
            self.assertIsNotNone(nd.get('bbox'))
            self.assertEqual(len(nd['bbox']), 4)

        # 2. Email addresses
        has_email = 'email' in types_found
        self.assertTrue(has_email, "Email address must be detected")
        email_det = types_found['email']
        self.assertIn('alice.walker', email_det['value'].lower())
        self.assertIsNotNone(email_det.get('bbox'))

        # 3. Phone numbers
        has_phone = 'phone' in types_found
        self.assertTrue(has_phone, "Phone number must be detected")
        phone_det = types_found['phone']
        self.assertIn('5678', phone_det['value'])
        self.assertIsNotNone(phone_det.get('bbox'))

        # 4. SSNs and identification numbers
        has_ssn = 'ssn' in types_found
        self.assertTrue(has_ssn, "SSN must be detected")
        ssn_det = types_found['ssn']
        self.assertIn('123', ssn_det['value'])
        self.assertIn('6789', ssn_det['value'])
        self.assertIsNotNone(ssn_det.get('bbox'))

        # 5. Credit/debit card numbers
        has_card = 'credit_card' in types_found
        self.assertTrue(has_card, "Credit/debit card number must be detected")
        card_det = types_found['credit_card']
        self.assertIn('4532', card_det['value'])
        self.assertIn('1239', card_det['value'])
        self.assertIsNotNone(card_det.get('bbox'))

        # 6. Expiration dates
        has_exp = 'expiration_date' in types_found
        self.assertTrue(has_exp, "Expiration date must be detected")
        exp_det = types_found['expiration_date']
        self.assertIn('08', exp_det['value'])
        self.assertIn('29', exp_det['value'])
        self.assertIsNotNone(exp_det.get('bbox'))

        # 7. Billing and residential addresses
        has_addr = 'address' in types_found
        self.assertTrue(has_addr, "Billing address must be detected")
        addr_det = types_found['address']
        self.assertIn('Evergreen Terrace', addr_det['value'])
        self.assertIsNotNone(addr_det.get('bbox'))

        # 8. QR Code
        has_qr = 'qr_code' in types_found
        self.assertTrue(has_qr, "QR code must be detected")
        qr_det = types_found['qr_code']
        self.assertIn('medicare-demo.org', qr_det['value'])
        self.assertIsNotNone(qr_det.get('bbox'))

    def test_pdf_attachment_sensitive_categories_detection(self):
        """Verify that PDF attachment detects all required sensitive categories."""
        if not os.path.exists(self.invoice_pdf):
            self.skipTest("Hospital invoice PDF not found.")

        result = self.scanner.scan_file(self.invoice_pdf, self.samples_dir)
        detections = result['detections']
        types_found = {d['type']: d for d in detections}

        self.assertIn('name', types_found, "Patient name must be detected in PDF")
        self.assertIn('email', types_found, "Email must be detected in PDF")
        self.assertIn('phone', types_found, "Phone must be detected in PDF")
        self.assertIn('ssn', types_found, "SSN must be detected in PDF")
        self.assertIn('credit_card', types_found, "Credit card must be detected in PDF")
        self.assertIn('expiration_date', types_found, "Expiration date must be detected in PDF")
        self.assertIn('address', types_found, "Billing address must be detected in PDF")
        self.assertIn('qr_code', types_found, "QR code must be detected in PDF")

    def test_auto_redact_endpoint_redacts_all_sensitive_categories(self):
        """End-to-end test of /api/auto-redact-attachment with fictional hospital billing invoice."""
        if not os.path.exists(self.invoice_img):
            self.skipTest("Hospital invoice image not found.")

        with open(self.invoice_img, 'rb') as f:
            file_bytes = f.read()

        response = self.client.post(
            '/api/auto-redact-attachment',
            data={'file': (io.BytesIO(file_bytes), 'hospital_invoice.png'), 'default_style': 'blackout'},
            content_type='multipart/form-data'
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertFalse(data['is_clean'])
        self.assertGreaterEqual(data['total_findings'], 7)

        # Verify that all detected items with bbox are marked redacted: True
        types_redacted = set()
        for det in data['detections']:
            if det.get('bbox') and len(det['bbox']) == 4:
                self.assertTrue(det.get('redacted'))
                types_redacted.add(det['type'])

        self.assertIn('name', types_redacted)
        self.assertIn('email', types_redacted)
        self.assertIn('phone', types_redacted)
        self.assertIn('ssn', types_redacted)
        self.assertIn('credit_card', types_redacted)
        self.assertIn('expiration_date', types_redacted)
        self.assertIn('address', types_redacted)
        self.assertIn('qr_code', types_redacted)

        # Verify sanitized copy is produced and verified non-recoverable
        self.assertTrue(data['non_recoverable_verified'])
        self.assertIn('sanitized_base64', data)
        self.assertGreater(len(data['sanitized_base64']), 100)

        # Verify sanitized image pixels are physically blacked out at every detected sensitive bounding box
        import base64
        from PIL import Image
        import numpy as np
        sanitized_img = Image.open(io.BytesIO(base64.b64decode(data['sanitized_base64'])))
        arr = np.array(sanitized_img)
        for det in data['detections']:
            bbox = det.get('bbox')
            if bbox:
                x, y, w, h = [int(round(v)) for v in bbox]
                cx = min(arr.shape[1] - 1, max(0, x + w // 2))
                cy = min(arr.shape[0] - 1, max(0, y + h // 2))
                pixel_rgb = arr[cy, cx][:3]
                self.assertEqual(list(pixel_rgb), [0, 0, 0], f"Redacted box for {det['type']} at ({cx}, {cy}) must be black")

if __name__ == '__main__':
    unittest.main()
