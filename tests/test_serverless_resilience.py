import unittest
import os
import sys
import json
import shutil
import pymupdf

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from core.cleanup import SessionManager
from config import Config

class TestServerlessResilience(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_stateless_session_reconstitution_on_cold_container(self):
        """Simulates a serverless container switch where /tmp was purged, verifying auto-reconstitution."""
        # 1. Initialize a demo session
        upload_resp = self.client.post('/upload', data={'sample_id': 'medical_invoice'})
        self.assertEqual(upload_resp.status_code, 200)
        data = json.loads(upload_resp.data)
        session_id = data['session_id']

        # Read session data
        upload_dir = SessionManager.get_session_upload_dir(session_id)
        info_path = os.path.join(upload_dir, 'session_info.json')
        with open(info_path, 'r', encoding='utf-8') as f:
            saved_session_data = json.load(f)

        # 2. SIMULATE CONTAINER WIPEOUT (wipe /tmp for this session)
        SessionManager.purge_session(session_id)
        self.assertFalse(os.path.exists(info_path))

        # 3. Client calls /api/redact/<session_id> passing saved_session_data
        redact_payload = {
            'session_id': session_id,
            'session_data': saved_session_data,
            'selected_detection_ids': [d['id'] for d in saved_session_data['detections']],
            'default_style': 'blackout',
            'manual_redactions': []
        }
        redact_resp = self.client.post(
            f'/api/redact/{session_id}',
            data=json.dumps(redact_payload),
            content_type='application/json'
        )
        self.assertEqual(redact_resp.status_code, 200, "Redaction must succeed via stateless re-hydration!")
        redact_data = json.loads(redact_resp.data)
        self.assertTrue(redact_data['success'])
        self.assertIn('redacted_previews_data', redact_data)
        self.assertIn('document_base64', redact_data)
        self.assertGreater(len(redact_data['document_base64']), 1000)

        # 4. SIMULATE OUTPUT WIPEOUT AGAIN, then test /download/<session_id>/document
        output_dir = SessionManager.get_session_output_dir(session_id)
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)

        doc_resp = self.client.get(f'/download/{session_id}/document')
        self.assertEqual(doc_resp.status_code, 200, "Download must auto-reconstitute missing file!")
        self.assertTrue(doc_resp.data.startswith(b'%PDF'))
        doc_resp.close()

        # 5. Clean up
        SessionManager.purge_session(session_id)

    def test_reestablish_session_endpoint(self):
        sample_session = {
            'file_name': 'medical_invoice.pdf',
            'sample_id': 'medical_invoice',
            'is_pdf': True
        }
        resp = self.client.post(
            '/api/re-establish-session/test_reest_123',
            data=json.dumps({'session_data': sample_session}),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        SessionManager.purge_session('test_reest_123')

if __name__ == '__main__':
    unittest.main()
