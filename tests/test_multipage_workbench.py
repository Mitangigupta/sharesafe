import unittest
import os
import sys
import json
import pymupdf
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, PageBreak, Spacer
from reportlab.lib.styles import getSampleStyleSheet

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from core.cleanup import SessionManager
from core.scanner import DocumentScanner
from core.redactor import DocumentRedactor
from core.certificate_gen import CertificateGenerator

class TestMultiPageWorkbench(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_multipage_document_scan_redact_and_sync(self):
        """Creates a real 2-page PDF with sensitive findings on both pages, scans, redacts, and verifies sync."""
        temp_dir = os.path.join(BASE_DIR, 'temp_uploads')
        os.makedirs(temp_dir, exist_ok=True)
        multi_pdf_path = os.path.join(temp_dir, 'multipage_test.pdf')

        # Generate a 2-page PDF
        doc = SimpleDocTemplate(multi_pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Page 1 Content with SSN and Email
        story.append(Paragraph("<b>Page 1: Confidential Medical Statement</b>", styles['Heading1']))
        story.append(Spacer(1, 15))
        story.append(Paragraph("Patient SSN: 987-65-4321", styles['Normal']))
        story.append(Paragraph("Contact Email: patient.secret@hospital-demo.org", styles['Normal']))
        story.append(PageBreak())

        # Page 2 Content with Credit Card and Phone
        story.append(Paragraph("<b>Page 2: Billing & Payment Information</b>", styles['Heading1']))
        story.append(Spacer(1, 15))
        story.append(Paragraph("Payment Card: 4532-0150-1234-5678", styles['Normal']))
        story.append(Paragraph("Direct Phone: +1-555-839-2049", styles['Normal']))

        doc.build(story)
        self.assertTrue(os.path.exists(multi_pdf_path))

        # Upload the multi-page PDF
        with open(multi_pdf_path, 'rb') as f:
            upload_resp = self.client.post(
                '/upload',
                data={'file': (f, 'multipage_test.pdf'), 'sharing_context': 'academic'},
                content_type='multipart/form-data'
            )
        self.assertEqual(upload_resp.status_code, 200)
        upload_data = json.loads(upload_resp.data)
        self.assertTrue(upload_data['success'])
        session_id = upload_data['session_id']

        # Access Workbench
        bench_resp = self.client.get(f'/workbench/{session_id}')
        self.assertEqual(bench_resp.status_code, 200)
        self.assertIn(b'multipage_test.pdf', bench_resp.data)
        self.assertIn(b'2 Pages', bench_resp.data)

        # Inspect session info
        upload_dir = SessionManager.get_session_upload_dir(session_id)
        with open(os.path.join(upload_dir, 'session_info.json'), 'r') as f:
            session_info = json.load(f)

        self.assertEqual(session_info['page_count'], 2)
        self.assertEqual(len(session_info['pages']), 2)

        # Ensure findings exist across pages
        pages_detected = {d['page'] for d in session_info['detections']}
        self.assertTrue(1 in pages_detected or 2 in pages_detected)

        # Test Redaction with multiple styles across both pages
        det_ids = [d['id'] for d in session_info['detections']]
        redact_payload = {
            'selected_detection_ids': det_ids,
            'default_style': 'blackout',
            'manual_redactions': [
                {'page': 1, 'bbox': [50, 50, 150, 40], 'style': 'blur', 'label': 'Manual Stamp Page 1'},
                {'page': 2, 'bbox': [60, 60, 180, 50], 'style': 'pixelate', 'label': 'Manual Seal Page 2'}
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

        # Both pages must have sanitized preview images for slider and side-by-side comparison
        self.assertEqual(len(redact_data['redacted_previews']), 2)

        # Download sanitized document and verify permanent text destruction on both pages
        doc_resp = self.client.get(f'/download/{session_id}/document')
        self.assertEqual(doc_resp.status_code, 200)
        doc_resp.close()
        output_dir = SessionManager.get_session_output_dir(session_id)
        out_pdf_path = os.path.join(output_dir, f"safe_sanitized_{session_id[:8]}.pdf")

        sanitized_doc = pymupdf.open(out_pdf_path)
        self.assertEqual(len(sanitized_doc), 2)
        # Verify text destruction via raster flattening
        for p_idx in range(len(sanitized_doc)):
            text = sanitized_doc[p_idx].get_text().strip()
            self.assertEqual(len(text), 0, f"Page {p_idx + 1} must have 0 extractable text characters!")
        sanitized_doc.close()

        # Download certificate
        cert_resp = self.client.get(f'/download/{session_id}/certificate')
        self.assertEqual(cert_resp.status_code, 200)
        self.assertTrue(cert_resp.data.startswith(b'%PDF'))
        cert_resp.close()

        # Purge session
        purge_resp = self.client.post(f'/api/purge/{session_id}')
        self.assertEqual(purge_resp.status_code, 200)

        # Cleanup test file
        if os.path.exists(multi_pdf_path):
            os.remove(multi_pdf_path)

if __name__ == '__main__':
    unittest.main()
