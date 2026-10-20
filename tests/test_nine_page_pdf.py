import unittest
import os
import sys
import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, PageBreak, Spacer
from reportlab.lib.styles import getSampleStyleSheet

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from core.cleanup import SessionManager
from core.redactor import DocumentRedactor

class TestNinePagePdfWorkbench(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_nine_page_pdf_lifecycle(self):
        """Generates a 9-page PDF, uploads it, verifies all 9 pages, draws boxes, redacts, and exports."""
        temp_dir = os.path.join(BASE_DIR, 'temp_uploads')
        os.makedirs(temp_dir, exist_ok=True)
        pdf_path = os.path.join(temp_dir, 'nine_page_test_doc.pdf')

        # Build 9-page PDF
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        sensitive_samples = [
            ("Page 1: Admission Record", "SSN: 111-22-3333"),
            ("Page 2: Insurance Policy", "Card: 4111-2222-3333-4444"),
            ("Page 3: Clinical Notes", "Email: doctor.smith@hospital-demo.org"),
            ("Page 4: Diagnostic Imaging", "MRN: MRN-998877"),
            ("Page 5: Medication History", "Prescription ID: RX-445566"),
            ("Page 6: Lab Findings", "Direct Phone: +1-555-019-2834"),
            ("Page 7: Surgical Record", "Surgeon Pin: 9876"),
            ("Page 8: Discharge Summary", "Billing Ref: INV-2026-9999"),
            ("Page 9: Final Compliance Review", "Audit Signature: SIG-VERIFIED-2026")
        ]

        for i, (title, secret) in enumerate(sensitive_samples):
            story.append(Paragraph(f"<b>{title}</b>", styles['Heading1']))
            story.append(Spacer(1, 20))
            story.append(Paragraph(f"Sensitive Entity: {secret}", styles['Normal']))
            story.append(Spacer(1, 15))
            story.append(Paragraph("This is standard mock content filling the body of the medical document for testing multi-page rendering and synchronization.", styles['Normal']))
            if i < len(sensitive_samples) - 1:
                story.append(PageBreak())

        doc.build(story)
        self.assertTrue(os.path.exists(pdf_path))

        # 1. Upload the 9-page PDF
        with open(pdf_path, 'rb') as f:
            upload_resp = self.client.post(
                '/upload',
                data={'file': (f, 'nine_page_test_doc.pdf'), 'sharing_context': 'academic'},
                content_type='multipart/form-data'
            )
        self.assertEqual(upload_resp.status_code, 200)
        upload_data = json.loads(upload_resp.data)
        self.assertTrue(upload_data['success'])
        session_id = upload_data['session_id']

        # 2. Check Workbench endpoint
        bench_resp = self.client.get(f'/workbench/{session_id}')
        self.assertEqual(bench_resp.status_code, 200)
        self.assertIn(b'nine_page_test_doc.pdf', bench_resp.data)
        self.assertIn(b'9 Pages', bench_resp.data)

        # 3. Check session data on disk
        upload_dir = SessionManager.get_session_upload_dir(session_id)
        with open(os.path.join(upload_dir, 'session_info.json'), 'r') as f:
            session_info = json.load(f)

        self.assertEqual(session_info['page_count'], 9)
        self.assertEqual(len(session_info['pages']), 9)

        # Verify preview image was rendered for each of the 9 pages
        for p in range(1, 10):
            preview_file = os.path.join(upload_dir, f"page_{p}.png")
            self.assertTrue(os.path.exists(preview_file), f"Page {p} preview missing")
            self.assertGreater(os.path.getsize(preview_file), 1000)

        # 4. Redaction test with manual boxes on Page 1 and Page 9
        det_ids = [d['id'] for d in session_info['detections']]
        redact_payload = {
            'selected_detection_ids': det_ids,
            'default_style': 'blackout',
            'manual_redactions': [
                {'id': 'man_1', 'page': 1, 'bbox': [100, 100, 200, 50], 'style': 'blur', 'label': 'Custom Box P1'},
                {'id': 'man_9', 'page': 9, 'bbox': [120, 150, 250, 60], 'style': 'pixelate', 'label': 'Custom Box P9'}
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
        self.assertIn('document_base64', redact_data)
        self.assertEqual(len(redact_data['redacted_previews_data']), 9)

        # 5. Verify all 9 pages have base64 previews
        for p_idx, b64 in enumerate(redact_data['redacted_previews_data']):
            self.assertTrue(b64.startswith('data:image/png;base64,'), f"Page {p_idx + 1} preview invalid")

        # Cleanup
        SessionManager.purge_session(session_id)
        if os.path.exists(pdf_path):
            os.remove(pdf_path)

if __name__ == '__main__':
    unittest.main()
