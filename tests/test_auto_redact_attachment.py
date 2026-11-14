import io
import json
import os
import unittest
from app import app, Config

class TestAutoRedactAttachment(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.sample_pdf = os.path.join(os.path.dirname(__file__), '..', 'samples', 'medical_invoice.pdf')
        self.sample_img = os.path.join(os.path.dirname(__file__), '..', 'samples', 'aadhaar_pan_sample.png')

    def test_unsupported_file_fails_with_informative_error(self):
        """Unsupported file types must fail and inform the user, never silently allowed as safe."""
        data = {
            'file': (io.BytesIO(b'malicious or unknown content'), 'payload.exe')
        }
        res = self.client.post('/api/auto-redact-attachment', data=data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 400)
        body = res.get_json()
        self.assertFalse(body.get('success', False))
        self.assertIn('Unsupported file format', body.get('error', ''))

    def test_auto_redact_pdf_attachment(self):
        """PDF attachment is scanned, automatically redacted, and verified non-recoverable."""
        if not os.path.exists(self.sample_pdf):
            self.skipTest(f"Sample PDF {self.sample_pdf} not found.")

        with open(self.sample_pdf, 'rb') as f:
            pdf_bytes = f.read()

        data = {
            'file': (io.BytesIO(pdf_bytes), 'medical_invoice.pdf'),
            'sharing_context': 'academic',
            'default_style': 'blackout'
        }
        res = self.client.post('/api/auto-redact-attachment', data=data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertTrue(body['success'])
        self.assertFalse(body['is_clean'])
        self.assertGreater(body['total_findings'], 0)
        self.assertTrue(body['non_recoverable_verified'])
        self.assertIn('sanitized_base64', body)
        self.assertIn('preview_data_url', body)
        self.assertEqual(body['verification_details']['residual_text_chars'], 0)

        # Check default redaction state: all items with bbox are marked redacted: True
        for d in body['detections']:
            if d.get('bbox') and len(d.get('bbox')) == 4:
                self.assertTrue(d.get('redacted'))
                self.assertEqual(d.get('style'), 'blackout')

        session_id = body['session_id']
        first_det_id = body['detections'][0]['id']

        # Test selective undo on first detection
        update_res = self.client.post(
            f'/api/update-attachment-redactions/{session_id}',
            json={'excluded_detection_ids': [first_det_id]}
        )
        self.assertEqual(update_res.status_code, 200)
        update_body = update_res.get_json()
        self.assertTrue(update_body['success'])
        # Verify first detection is now marked redacted: False
        for d in update_body['detections']:
            if d['id'] == first_det_id:
                self.assertFalse(d['redacted'])
        self.assertTrue(update_body['non_recoverable_verified'])

    def test_auto_redact_image_attachment(self):
        """Image attachment is scanned, automatically redacted, and metadata stripped."""
        if not os.path.exists(self.sample_img):
            self.skipTest(f"Sample image {self.sample_img} not found.")

        with open(self.sample_img, 'rb') as f:
            img_bytes = f.read()

        data = {
            'file': (io.BytesIO(img_bytes), 'aadhaar_pan_sample.png'),
            'sharing_context': 'academic',
            'default_style': 'blur'
        }
        res = self.client.post('/api/auto-redact-attachment', data=data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertTrue(body['success'])
        self.assertIn('sanitized_base64', body)
        self.assertTrue(body['non_recoverable_verified'])

if __name__ == '__main__':
    unittest.main()
