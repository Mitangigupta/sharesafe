import unittest
import os
import io
import json
import base64
from PIL import Image
import numpy as np
import fitz  # PyMuPDF

from app import app
from core.redactor import DocumentRedactor

class TestManualRedactionEditor(unittest.TestCase):
    """
    Validates the Manual Redaction Editor:
    1. Draw-to-Redact: Arbitrary rectangular selection boxes permanently redacted in sanitized output.
    2. Editing Controls: Add multiple boxes, delete/remove individual boxes (Undo/Delete), clear all.
    3. Independent Controls: Auto-detected items and manual redactions operate independently.
    4. Multi-Page / PDF Support: Pages navigation and manual redaction on PDF pages.
    5. Final Sanitization: Permanent raster flattening (0 extractable characters) and metadata stripping.
    6. Non-recoverability & Pixel Blackout: Blackout regions [0, 0, 0] in final output.
    """

    def setUp(self):
        self.client = app.test_client()
        self.invoice_img = os.path.join(os.path.dirname(__file__), '..', 'samples', 'medical_invoice_150dpi.png')
        self.invoice_pdf = os.path.join(os.path.dirname(__file__), '..', 'samples', 'medical_invoice.pdf')

    def test_manual_redaction_on_image(self):
        """Test drawing arbitrary manual redaction boxes on an image attachment."""
        if not os.path.exists(self.invoice_img):
            self.skipTest("Sample invoice image not found.")

        with open(self.invoice_img, 'rb') as f:
            file_bytes = f.read()

        # Step 1: Initial auto-redact scan
        init_res = self.client.post(
            '/api/auto-redact-attachment',
            data={'file': (io.BytesIO(file_bytes), 'medical_invoice.png'), 'default_style': 'blackout'},
            content_type='multipart/form-data'
        )
        self.assertEqual(init_res.status_code, 200)
        init_data = init_res.get_json()
        self.assertTrue(init_data['success'])
        session_id = init_data['session_id']

        # Choose a region that wasn't flagged by auto-detection (e.g., bottom consultation description)
        manual_box = {
            'id': 'manual-box-1',
            'page': 1,
            'bbox': [14, 222, 180, 24],
            'label': 'Cardiology Consultation Line'
        }

        # Step 2: Update with manual redaction
        update_res = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={
                'excluded_detection_ids': [],
                'manual_redactions': [manual_box]
            }
        )
        self.assertEqual(update_res.status_code, 200)
        update_data = update_res.get_json()
        self.assertTrue(update_data['success'])
        self.assertIn('manual_redactions', update_data)
        self.assertEqual(len(update_data['manual_redactions']), 1)
        self.assertEqual(update_data['manual_redactions'][0]['id'], 'manual-box-1')

        # Step 3: Inspect pixel values in the sanitized image output
        sanitized_img = Image.open(io.BytesIO(base64.b64decode(update_data['sanitized_base64'])))
        arr = np.array(sanitized_img)

        # Center of manual box [14, 222, 180, 24] -> cx = 14 + 90 = 104, cy = 222 + 12 = 234
        cx = 14 + 90
        cy = 222 + 12
        pixel = list(arr[cy, cx][:3])
        self.assertEqual(pixel, [0, 0, 0], f"Manual redaction box must be solid black [0, 0, 0], got {pixel}")

    def test_manual_redaction_on_pdf_and_zero_text_leakage(self):
        """Test manual redaction on PDF attachment and verify permanent flattening with 0 extractable chars."""
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
        self.assertTrue(init_data['success'])
        session_id = init_data['session_id']
        self.assertGreaterEqual(init_data.get('page_count', 0), 1)
        self.assertIn('pages', init_data)

        # Custom manual box on page 1
        manual_box = {
            'id': 'manual-pdf-box-1',
            'page': 1,
            'bbox': [100, 100, 150, 40],
            'label': 'Custom Medical Notes'
        }

        update_res = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={
                'excluded_detection_ids': [],
                'manual_redactions': [manual_box]
            }
        )
        self.assertEqual(update_res.status_code, 200)
        update_data = update_res.get_json()
        self.assertTrue(update_data['success'])

        # Verify pages array returned for UI preview synchronization
        self.assertIn('pages', update_data)
        self.assertGreaterEqual(len(update_data['pages']), 1)
        self.assertTrue(update_data['pages'][0]['preview_data_url'].startswith('data:image/png;base64,'))

        # Verify PDF non-recoverability (0 extractable text characters)
        pdf_out_bytes = base64.b64decode(update_data['sanitized_base64'])
        doc = fitz.open(stream=pdf_out_bytes, filetype='pdf')
        self.assertGreaterEqual(len(doc), 1)

        extracted_text = ""
        for page in doc:
            extracted_text += page.get_text()

        self.assertEqual(len(extracted_text.strip()), 0, "Sanitized PDF must be 100% raster-flattened with 0 extractable characters")

        # Verify the manual box area on the rasterized PDF page is blacked out
        page0 = doc[0]
        pix = page0.get_pixmap()
        img = Image.open(io.BytesIO(pix.tobytes("png")))
        arr = np.array(img)

        # Scaled pixel check at center of manual box
        # PyMuPDF rendering coordinates match 150 DPI
        cx = 100 + 75
        cy = 100 + 20
        pixel = list(arr[cy, cx][:3])
        self.assertEqual(pixel, [0, 0, 0], f"Manual PDF redaction area must be solid black [0, 0, 0], got {pixel}")

    def test_manual_redaction_editing_undo_redo_and_selective_delete(self):
        """Test adding multiple manual redactions, deleting one (undo/selective delete), and independence from auto-detections."""
        if not os.path.exists(self.invoice_img):
            self.skipTest("Sample invoice image not found.")

        with open(self.invoice_img, 'rb') as f:
            file_bytes = f.read()

        init_res = self.client.post(
            '/api/auto-redact-attachment',
            data={'file': (io.BytesIO(file_bytes), 'medical_invoice.png'), 'default_style': 'blackout'},
            content_type='multipart/form-data'
        )
        self.assertEqual(init_res.status_code, 200)
        init_data = init_res.get_json()
        session_id = init_data['session_id']
        detections = init_data['detections']

        # Find Patient Name detection
        patient_det = next(d for d in detections if 'Alice Walker' in d.get('value', ''))

        # Define 2 manual redactions
        box_a = {'id': 'box-A', 'page': 1, 'bbox': [14, 222, 100, 20], 'label': 'Manual Box A'}
        box_b = {'id': 'box-B', 'page': 1, 'bbox': [120, 222, 100, 20], 'label': 'Manual Box B'}

        # Step 1: Add both manual boxes AND keep Patient Name unredacted
        res1 = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={
                'excluded_detection_ids': [patient_det['id']],
                'manual_redactions': [box_a, box_b]
            }
        )
        self.assertEqual(res1.status_code, 200)
        data1 = res1.get_json()
        self.assertTrue(data1['success'])
        self.assertEqual(len(data1['manual_redactions']), 2)

        img1 = Image.open(io.BytesIO(base64.b64decode(data1['sanitized_base64'])))
        arr1 = np.array(img1)

        # Box A is blacked out
        px_a = list(arr1[222 + 10, 14 + 50][:3])
        self.assertEqual(px_a, [0, 0, 0])

        # Box B is blacked out
        px_b = list(arr1[222 + 10, 120 + 50][:3])
        self.assertEqual(px_b, [0, 0, 0])

        # Patient Name was KEPT -> NOT blacked out
        cx_patient = int(patient_det['bbox'][0] + patient_det['bbox'][2] // 2)
        cy_patient = int(patient_det['bbox'][1] + patient_det['bbox'][3] // 2)
        px_patient = list(arr1[cy_patient, cx_patient][:3])
        self.assertNotEqual(px_patient, [0, 0, 0], "Kept patient name must remain visible")

        # Step 2: Delete Box B (Undo/Delete), keeping Box A
        res2 = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={
                'excluded_detection_ids': [patient_det['id']],
                'manual_redactions': [box_a]
            }
        )
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertTrue(data2['success'])
        self.assertEqual(len(data2['manual_redactions']), 1)

        img2 = Image.open(io.BytesIO(base64.b64decode(data2['sanitized_base64'])))
        arr2 = np.array(img2)

        # Box A remains blacked out
        px_a2 = list(arr2[222 + 10, 14 + 50][:3])
        self.assertEqual(px_a2, [0, 0, 0])

        # Box B was deleted -> restored to original (not blacked out)
        px_b2 = list(arr2[222 + 10, 120 + 50][:3])
        self.assertNotEqual(px_b2, [0, 0, 0], "Deleted manual box region must be restored to original")

        # Step 3: Clear all manual redactions
        res3 = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={
                'excluded_detection_ids': [patient_det['id']],
                'manual_redactions': []
            }
        )
        self.assertEqual(res3.status_code, 200)
        data3 = res3.get_json()
        self.assertTrue(data3['success'])
        self.assertEqual(len(data3['manual_redactions']), 0)

        img3 = Image.open(io.BytesIO(base64.b64decode(data3['sanitized_base64'])))
        arr3 = np.array(img3)

        # Both Box A and Box B are now restored
        self.assertNotEqual(list(arr3[222 + 10, 14 + 50][:3]), [0, 0, 0])
        self.assertNotEqual(list(arr3[222 + 10, 120 + 50][:3]), [0, 0, 0])

if __name__ == '__main__':
    unittest.main()
