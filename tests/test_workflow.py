import unittest
import os
import sys
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from core.cleanup import SessionManager

class TestShareSafeWorkflow(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_homepage_render(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'ShareSafe', response.data)
        self.assertIn(b'Try Preloaded Fictional Demo Samples', response.data)

    def test_ocr_status_api(self):
        response = self.client.get('/api/ocr-status')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('available', data)
        self.assertIn('message', data)

    def test_end_to_end_upload_scan_redact_download_flow(self):
        # 1. Upload sample demo document (Medical Invoice)
        upload_resp = self.client.post('/upload', data={'sample_id': 'medical_invoice'})
        self.assertEqual(upload_resp.status_code, 200)
        upload_data = json.loads(upload_resp.data)
        self.assertTrue(upload_data['success'])
        session_id = upload_data['session_id']

        # 2. Access Workbench page
        bench_resp = self.client.get(f'/workbench/{session_id}')
        self.assertEqual(bench_resp.status_code, 200)
        self.assertIn(b'Threat Score', bench_resp.data)

        # 3. Read session info to get detection IDs
        upload_dir = SessionManager.get_session_upload_dir(session_id)
        with open(os.path.join(upload_dir, 'session_info.json'), 'r') as f:
            session_info = json.load(f)

        det_ids = [d['id'] for d in session_info['detections']]
        self.assertGreater(len(det_ids), 0)

        # 4. Trigger Redaction with custom style and manual rectangle
        redact_payload = {
            'selected_detection_ids': det_ids,
            'default_style': 'blur',
            'manual_redactions': [
                {'page': 1, 'bbox': [100, 100, 200, 50], 'style': 'blackout', 'label': 'Manual Notes'}
            ]
        }
        redact_resp = self.client.post(
            f'/api/redact/{session_id}',
            data=json.dumps(redact_payload),
            content_type='application/json'
        )
        self.assertEqual(redact_resp.status_code, 200)
        redact_data = json.loads(redact_resp.data)
        self.assertTrue(redact_data['success'])
        self.assertIn('redacted_previews', redact_data)
        self.assertIn('audit_data', redact_data)

        # 5. Download Sanitized Document
        doc_resp = self.client.get(f'/download/{session_id}/document')
        self.assertEqual(doc_resp.status_code, 200)
        self.assertGreater(len(doc_resp.data), 1000)
        doc_resp.close()

        # 6. Download Audit Certificate
        cert_resp = self.client.get(f'/download/{session_id}/certificate')
        self.assertEqual(cert_resp.status_code, 200)
        self.assertTrue(cert_resp.data.startswith(b'%PDF'))
        cert_resp.close()

        # 7. Purge Session
        purge_resp = self.client.post(f'/api/purge/{session_id}')
        self.assertEqual(purge_resp.status_code, 200)
        purge_data = json.loads(purge_resp.data)
        self.assertTrue(purge_data['success'])

    def test_image_upload_scan_redact_flow(self):
        # Test real image file upload via multipart/form-data
        sample_img_path = os.path.join(BASE_DIR, 'samples', 'aadhaar_pan_sample.png')
        with open(sample_img_path, 'rb') as f:
            upload_resp = self.client.post(
                '/upload',
                data={
                    'file': (f, 'test_identity_card.png'),
                    'sharing_context': 'academic'
                },
                content_type='multipart/form-data'
            )
        self.assertEqual(upload_resp.status_code, 200)
        upload_data = json.loads(upload_resp.data)
        self.assertTrue(upload_data['success'])
        session_id = upload_data['session_id']

        # Access workbench
        bench_resp = self.client.get(f'/workbench/{session_id}')
        self.assertEqual(bench_resp.status_code, 200)
        self.assertIn(b'test_identity_card.png', bench_resp.data)

        # Trigger Redaction
        redact_resp = self.client.post(
            f'/api/redact/{session_id}',
            data=json.dumps({
                'selected_detection_ids': [],
                'default_style': 'blackout',
                'manual_redactions': [{'page': 1, 'bbox': [10, 10, 50, 20], 'style': 'blackout', 'label': 'Test'}]
            }),
            content_type='application/json'
        )
        self.assertEqual(redact_resp.status_code, 200)
        redact_data = json.loads(redact_resp.data)
        self.assertTrue(redact_data['success'])

        # Download document
        doc_resp = self.client.get(f'/download/{session_id}/document')
        self.assertEqual(doc_resp.status_code, 200)
        self.assertGreater(len(doc_resp.data), 1000)
        doc_resp.close()

        # Purge
        self.client.post(f'/api/purge/{session_id}')

if __name__ == '__main__':
    unittest.main()

