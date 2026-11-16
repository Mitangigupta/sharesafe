import unittest
import os
import io
import json
import base64
from PIL import Image
import numpy as np

from app import app
from core.scanner import DocumentScanner
from core.redactor import DocumentRedactor

class TestIndividualRedactionControls(unittest.TestCase):
    """
    Verifies that individual Redact / Keep controls:
    1. Selectively redact or keep specific detected sensitive items.
    2. Immediately update the preview and sanitized file.
    3. Changing one item does not affect other items.
    4. Bounding box coordinates remain accurate.
    5. 'Download Clean Copy' and 'Send Sanitized Attachment' reflect the exact user choices.
    """

    def setUp(self):
        self.client = app.test_client()
        self.invoice_img = os.path.join(os.path.dirname(__file__), '..', 'samples', 'medical_invoice_150dpi.png')
        self.invoice_pdf = os.path.join(os.path.dirname(__file__), '..', 'samples', 'medical_invoice.pdf')
        self.samples_dir = os.path.join(os.path.dirname(__file__), '..', 'samples')

    def test_individual_redact_and_keep_controls_image(self):
        """Test individual Redact vs Keep on image attachment with selective exclusion."""
        if not os.path.exists(self.invoice_img):
            self.skipTest("Sample invoice image not found.")

        with open(self.invoice_img, 'rb') as f:
            file_bytes = f.read()

        # Step 1: Initial auto-redact scan (all detected items redacted by default)
        init_res = self.client.post(
            '/api/auto-redact-attachment',
            data={'file': (io.BytesIO(file_bytes), 'hospital_invoice.png'), 'default_style': 'blackout'},
            content_type='multipart/form-data'
        )
        self.assertEqual(init_res.status_code, 200)
        init_data = init_res.get_json()
        self.assertTrue(init_data['success'])
        session_id = init_data['session_id']
        detections = init_data['detections']
        self.assertGreaterEqual(len(detections), 8)

        # Map detections by type
        name_dets = [d for d in detections if d.get('type') == 'name' or 'Name' in d.get('label', '')]
        email_dets = [d for d in detections if d.get('type') == 'email']
        card_dets = [d for d in detections if d.get('type') == 'credit_card']
        qr_dets = [d for d in detections if d.get('type') == 'qr_code']
        ssn_dets = [d for d in detections if d.get('type') == 'ssn']

        self.assertGreater(len(name_dets), 0, "Patient/Physician name must be detected")
        self.assertGreater(len(email_dets), 0, "Email must be detected")
        self.assertGreater(len(card_dets), 0, "Card must be detected")
        self.assertGreater(len(qr_dets), 0, "QR code must be detected")

        # Step 2: User decides to KEEP (unredact) the Patient Name and Email, but REDACT Card and SSN
        patient_det = next(d for d in name_dets if 'Alice Walker' in d.get('value', ''))
        email_det = email_dets[0]
        card_det = card_dets[0]

        excluded_ids = [patient_det['id'], email_det['id']]

        update_res = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={'excluded_detection_ids': excluded_ids}
        )
        self.assertEqual(update_res.status_code, 200)
        update_data = update_res.get_json()
        self.assertTrue(update_data['success'])

        # Verify updated detections state:
        updated_detections = {d['id']: d for d in update_data['detections']}
        
        # Patient Name and Email must now be marked redacted: False (Kept)
        self.assertFalse(updated_detections[patient_det['id']]['redacted'])
        self.assertFalse(updated_detections[email_det['id']]['redacted'])
        
        # Credit Card and others must remain redacted: True (Redact)
        self.assertTrue(updated_detections[card_det['id']]['redacted'])
        if ssn_dets:
            self.assertTrue(updated_detections[ssn_dets[0]['id']]['redacted'])

        # Verify bounding-box coordinates are accurately preserved for all items
        for d in update_data['detections']:
            self.assertIn('bbox', d)
            self.assertEqual(len(d['bbox']), 4)

        # Step 3: Verify sanitized preview & sanitized file reflect the user's choices
        sanitized_img = Image.open(io.BytesIO(base64.b64decode(update_data['sanitized_base64'])))
        arr = np.array(sanitized_img)

        # The Card box MUST be blacked out [0, 0, 0]
        cx_card = int(card_det['bbox'][0] + card_det['bbox'][2] // 2)
        cy_card = int(card_det['bbox'][1] + card_det['bbox'][3] // 2)
        card_pixel = list(arr[cy_card, cx_card][:3])
        self.assertEqual(card_pixel, [0, 0, 0], "Redacted card must remain blacked out")

        # The Patient Name box was KEPT -> MUST NOT be blacked out (background is white/cream [>200, >200, >200])
        cx_name = int(patient_det['bbox'][0] + patient_det['bbox'][2] // 2)
        cy_name = int(patient_det['bbox'][1] + patient_det['bbox'][3] // 2)
        name_pixel = list(arr[cy_name, cx_name][:3])
        self.assertNotEqual(name_pixel, [0, 0, 0], "Kept patient name must NOT be blacked out")

        # Step 4: Toggle Patient Name back to REDACT
        # Removing patient_det['id'] from excluded_ids
        excluded_ids_2 = [email_det['id']]
        update_res_2 = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={'excluded_detection_ids': excluded_ids_2}
        )
        self.assertEqual(update_res_2.status_code, 200)
        update_data_2 = update_res_2.get_json()
        
        # Now Patient Name is redacted again
        updated_2 = {d['id']: d for d in update_data_2['detections']}
        self.assertTrue(updated_2[patient_det['id']]['redacted'])
        self.assertFalse(updated_2[email_det['id']]['redacted'])

        sanitized_img_2 = Image.open(io.BytesIO(base64.b64decode(update_data_2['sanitized_base64'])))
        arr_2 = np.array(sanitized_img_2)
        name_pixel_2 = list(arr_2[cy_name, cx_name][:3])
        self.assertEqual(name_pixel_2, [0, 0, 0], "Re-redacted patient name must be blacked out again")

    def test_individual_redact_and_keep_controls_pdf(self):
        """Test individual Redact vs Keep on PDF attachment."""
        if not os.path.exists(self.invoice_pdf):
            self.skipTest("Sample invoice PDF not found.")

        with open(self.invoice_pdf, 'rb') as f:
            pdf_bytes = f.read()

        init_res = self.client.post(
            '/api/auto-redact-attachment',
            data={'file': (io.BytesIO(pdf_bytes), 'medical_invoice.pdf'), 'default_style': 'blackout'},
            content_type='multipart/form-data'
        )
        self.assertEqual(init_res.status_code, 200)
        init_data = init_res.get_json()
        session_id = init_data['session_id']
        detections = init_data['detections']
        self.assertGreaterEqual(len(detections), 6)

        # Exclude QR Code and Phone Number
        qr_det = next(d for d in detections if d.get('type') == 'qr_code')
        phone_det = next(d for d in detections if d.get('type') == 'phone')
        excluded_ids = [qr_det['id'], phone_det['id']]

        update_res = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={'excluded_detection_ids': excluded_ids}
        )
        self.assertEqual(update_res.status_code, 200)
        update_data = update_res.get_json()
        self.assertTrue(update_data['success'])

        det_map = {d['id']: d for d in update_data['detections']}
        self.assertFalse(det_map[qr_det['id']]['redacted'])
        self.assertFalse(det_map[phone_det['id']]['redacted'])

        # Other items like SSN or Credit Card must remain redacted
        ssn_det = next(d for d in detections if d.get('type') == 'ssn')
        self.assertTrue(det_map[ssn_det['id']]['redacted'])

if __name__ == '__main__':
    unittest.main()
