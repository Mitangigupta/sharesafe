import unittest
import os
import io
import sys
import tempfile
import shutil
import json
import numpy as np
import cv2
from PIL import Image
import pymupdf
import qrcode

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app, validate_file_content
from core.regex_detector import SensitiveDetector
from core.qr_detector import QRDetector
from core.risk_assessor import RiskAssessor
from core.scanner import DocumentScanner
from core.cleanup import SessionManager

class RegressionTestSuite(unittest.TestCase):
    """Regression test suite for detection accuracy, scoring consistency, cross-device file handling, and UI alignment."""

    def setUp(self):
        self.detector = SensitiveDetector()
        self.qr_detector = QRDetector()
        self.scanner = DocumentScanner()
        self.client = app.test_client()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. A document with a valid email address
    def test_01_valid_email_detection(self):
        text = "For security inquiries, please contact devops.lead+audit@enterprise-cloud.co.uk."
        findings = self.detector.scan_text(text)
        email_findings = [f for f in findings if f['type'] == 'email']

        self.assertEqual(len(email_findings), 1)
        self.assertEqual(email_findings[0]['value'], 'devops.lead+audit@enterprise-cloud.co.uk')
        self.assertEqual(email_findings[0]['risk'], 'LOW')
        self.assertEqual(email_findings[0]['category'], 'Contact Information')
        self.assertIn('d***t@enterprise-cloud.co.uk', email_findings[0]['masked'])

    # 2. A document containing a valid phone number
    def test_02_valid_phone_number_detection(self):
        text_in = "Emergency Support Line: +91 98765 43210 available 24/7."
        findings_in = self.detector.scan_text(text_in)
        in_phone = [f for f in findings_in if f['type'] == 'phone']
        self.assertEqual(len(in_phone), 1)
        self.assertEqual(in_phone[0]['label'], 'Phone Number (IN)')
        self.assertEqual(in_phone[0]['risk'], 'MEDIUM')

        text_intl = "US Office Contact: +1 555-019-2834."
        findings_intl = self.detector.scan_text(text_intl)
        intl_phone = [f for f in findings_intl if f['type'] == 'phone']
        self.assertEqual(len(intl_phone), 1)
        self.assertEqual(intl_phone[0]['label'], 'Phone Number (Intl)')
        self.assertEqual(intl_phone[0]['risk'], 'MEDIUM')

    # 3. A document containing ordinary numbers that should not trigger false positives
    def test_03_ordinary_numbers_no_false_positives(self):
        lab_code_text = (
            "Operating Systems Lab Manual\n"
            "EXPERIMENT 7: String Operations & Performance Comparison\n"
            "1. Shell Script Implementation (exp5.sh)\n"
            "#!/bin/bash\n"
            "echo \"Enter a String\"\n"
            "read str\n"
            "echo \"Length of String: ${#str}\"\n"
            "echo \"Enter String Position:\"\n"
            "read start\n"
            "echo \"Enter Number of character:\"\n"
            "read length\n"
            "echo -n \"Substring: \"\n"
            "echo \"${str:$start:$length}\"\n"
            "gcc version 11.2.0.1, Python 3.11.4\n"
            "Execution completed in 120 ms. Memory allocated: 4096 bytes.\n"
            "Timestamp: 1729000000. Error code: 404.\n"
            "Price per unit: $125.00, Total invoice: Rs. 50000.\n"
        )
        findings = self.detector.scan_text(lab_code_text)
        # Should have zero critical or high false positives (no Aadhaar, no PAN, no credit cards, no phone numbers)
        critical_or_high = [f for f in findings if f.get('risk') in ('CRITICAL', 'HIGH')]
        self.assertEqual(len(critical_or_high), 0, f"Unexpected false positives found: {critical_or_high}")
        assessment = RiskAssessor.assess(findings)
        self.assertIn(assessment['level'], ('CLEAN', 'LOW'))

    # 4. A document containing a number that resembles an identifier but lacks sufficient evidence for a specific classification
    def test_04_identifier_lacking_evidence_not_labeled_aadhaar(self):
        # 12 digits formatted 4-4-4, but not an Aadhaar number (invalid checksum and no Aadhaar context)
        text = "Tracking reference code: 2024-5819-3712 found in shipment manifest."
        findings = self.detector.scan_text(text)
        
        # Must NOT be labeled as Indian Aadhaar UID
        aadhaar_matches = [f for f in findings if f.get('label') == 'Indian Aadhaar UID']
        self.assertEqual(len(aadhaar_matches), 0, "Non-Aadhaar number was incorrectly labeled as Indian Aadhaar UID!")

        # If detected as an identifier candidate, it must be marked as low/medium with review_required=True
        id_candidates = [f for f in findings if 'candidate' in f.get('label', '').lower()]
        if id_candidates:
            self.assertTrue(id_candidates[0].get('review_required', False))
            self.assertEqual(id_candidates[0].get('risk'), 'LOW')

    # 5. A QR code with an ordinary URL
    def test_05_qr_code_with_ordinary_url(self):
        qr = qrcode.QRCode(version=1, box_size=8, border=2)
        qr.add_data("https://github.com/mitangigupta/sharesafe/documentation")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img_np = cv2.cvtColor(np.array(img.convert('RGB')), cv2.COLOR_RGB2BGR)

        detections = self.qr_detector.detect(img_np)
        self.assertEqual(len(detections), 1)
        det = detections[0]
        self.assertEqual(det['type'], 'qr_code')
        self.assertEqual(det['label'], 'Web URL Link QR')
        self.assertEqual(det['risk'], 'LOW')
        self.assertFalse(det.get('review_required', True))

    # 6. A QR code with a payload containing sensitive information
    def test_06_qr_code_with_sensitive_payload(self):
        # URL containing an AWS API key credential
        sensitive_payload = "https://internal-api.example.com/v1/auth?api_key=AKIAIOSFODNN7EXAMPLE&redirect=dashboard"
        qr = qrcode.QRCode(version=2, box_size=8, border=2)
        qr.add_data(sensitive_payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img_np = cv2.cvtColor(np.array(img.convert('RGB')), cv2.COLOR_RGB2BGR)

        detections = self.qr_detector.detect(img_np)
        self.assertEqual(len(detections), 1)
        det = detections[0]
        # Must be flagged with CRITICAL or HIGH risk due to the AWS key inside payload
        self.assertEqual(det['risk'], 'CRITICAL')
        self.assertIn('AKIA', det['details'])

    # 7. A multi-page PDF with findings on different pages
    def test_07_multipage_pdf_page_isolation(self):
        pdf_path = os.path.join(self.temp_dir, "multipage_sample.pdf")
        doc = pymupdf.open()

        # Page 1: Email
        p1 = doc.new_page(width=595, height=842)
        p1.insert_text((50, 100), "Confidential contact: support-agent@fintech-demo.io", fontsize=12)

        # Page 2: Phone Number
        p2 = doc.new_page(width=595, height=842)
        p2.insert_text((50, 100), "Customer care hotline: +1 555-432-8765 for assistance.", fontsize=12)

        # Page 3: IP Address
        p3 = doc.new_page(width=595, height=842)
        p3.insert_text((50, 100), "Server network interface: 10.240.12.89 subnet.", fontsize=12)

        doc.save(pdf_path)
        doc.close()

        scan_result = self.scanner.scan_file(pdf_path, self.temp_dir, sharing_context='professional')
        self.assertEqual(scan_result['page_count'], 3)

        detections = scan_result['detections']
        p1_dets = [d for d in detections if d.get('page') == 1]
        p2_dets = [d for d in detections if d.get('page') == 2]
        p3_dets = [d for d in detections if d.get('page') == 3]

        self.assertGreaterEqual(len(p1_dets), 1)
        self.assertGreaterEqual(len(p2_dets), 1)
        self.assertGreaterEqual(len(p3_dets), 1)
        self.assertEqual(p1_dets[0]['type'], 'email')
        self.assertEqual(p2_dets[0]['type'], 'phone')
        self.assertEqual(p3_dets[0]['type'], 'ip_address')

    # 8. A scanned PDF requiring OCR
    def test_08_scanned_pdf_handling(self):
        # Create a PDF where page content is pure raster image (no text stream)
        pdf_path = os.path.join(self.temp_dir, "scanned_invoice.pdf")
        doc = pymupdf.open()
        page = doc.new_page(width=595, height=842)

        # Create image with text
        img = Image.new('RGB', (595, 842), color=(255, 255, 255))
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        page.insert_image(page.rect, stream=img_bytes.getvalue())
        doc.save(pdf_path)
        doc.close()

        # Scanning should handle scanned pages cleanly without raising unhandled errors
        scan_result = self.scanner.scan_file(pdf_path, self.temp_dir)
        self.assertEqual(scan_result['page_count'], 1)
        self.assertIn('pages', scan_result)
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, "page_1.png")))

    # 9. An image with rotated dimensions
    def test_09_image_with_rotated_dimensions(self):
        # Wide landscape image
        img_path = os.path.join(self.temp_dir, "wide_diagram.png")
        img = Image.new('RGB', (1600, 600), color=(240, 240, 245))
        img.save(img_path)

        scan_result = self.scanner.scan_file(img_path, self.temp_dir)
        self.assertEqual(scan_result['is_pdf'], False)
        self.assertEqual(scan_result['page_count'], 1)
        self.assertEqual(scan_result['pages'][0]['width'], 1600)
        self.assertEqual(scan_result['pages'][0]['height'], 600)

    # 10. Two consecutive uploads to verify that findings do not leak between files
    def test_10_no_leakage_between_consecutive_uploads(self):
        # Upload 1: Document containing SSN (CRITICAL)
        file1_data = io.BytesIO(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")
        # Use PyMuPDF to create valid PDF with SSN
        pdf1_path = os.path.join(self.temp_dir, "doc1.pdf")
        doc1 = pymupdf.open()
        p1 = doc1.new_page(width=595, height=842)
        p1.insert_text((50, 100), "Sensitive SSN Record: 123-45-6789.", fontsize=12)
        doc1.save(pdf1_path)
        doc1.close()

        with open(pdf1_path, 'rb') as f1:
            res1 = self.client.post('/upload', data={'file': (f1, 'doc1.pdf')})
        self.assertEqual(res1.status_code, 200)
        json1 = res1.get_json()
        session1_id = json1['session_id']

        # Upload 2: Completely clean document with no sensitive data
        pdf2_path = os.path.join(self.temp_dir, "doc2.pdf")
        doc2 = pymupdf.open()
        p2 = doc2.new_page(width=595, height=842)
        p2.insert_text((50, 100), "Ordinary coursework notes. No private data.", fontsize=12)
        doc2.save(pdf2_path)
        doc2.close()

        with open(pdf2_path, 'rb') as f2:
            res2 = self.client.post('/upload', data={'file': (f2, 'doc2.pdf')})
        self.assertEqual(res2.status_code, 200)
        json2 = res2.get_json()
        session2_id = json2['session_id']

        # Ensure different session IDs
        self.assertNotEqual(session1_id, session2_id)

        # Inspect session 2 info on disk
        s2_dir = SessionManager.get_session_upload_dir(session2_id)
        with open(os.path.join(s2_dir, 'session_info.json'), 'r', encoding='utf-8') as sf:
            s2_data = json.load(sf)

        # Verify no findings leaked from doc1 to doc2
        self.assertEqual(len(s2_data['detections']), 0)
        self.assertEqual(s2_data['risk_summary']['level'], 'CLEAN')
        self.assertEqual(s2_data['risk_summary']['score'], 0)

    # 11. A malformed or unsupported file
    def test_11_malformed_and_unsupported_files(self):
        # Unsupported file extension (.exe)
        res_exe = self.client.post('/upload', data={
            'file': (io.BytesIO(b"MZ\x90\x00"), 'malware.exe')
        })
        self.assertEqual(res_exe.status_code, 400)
        self.assertIn('error', res_exe.get_json())

        # Malformed PDF with corrupt header
        res_corrupt = self.client.post('/upload', data={
            'file': (io.BytesIO(b"<html><body>Not a PDF</body></html>"), 'fake.pdf')
        })
        self.assertEqual(res_corrupt.status_code, 400)
        self.assertIn('error', res_corrupt.get_json())

    # 12. A document with overlapping detections to verify deduplication
    def test_12_overlapping_detections_deduplicated(self):
        # Duplicate overlapping boxes with same and differing categories
        detections = [
            {
                'id': 'det_1',
                'page': 1,
                'bbox': [100.0, 200.0, 150.0, 25.0],
                'value': '+91 98765 43210',
                'type': 'phone',
                'risk': 'MEDIUM',
                'confidence': 'high'
            },
            {
                'id': 'det_2',
                'page': 1,
                'bbox': [102.0, 201.0, 146.0, 23.0],
                'value': '98765 43210',
                'type': 'phone',
                'risk': 'MEDIUM',
                'confidence': 'medium'
            },
            {
                'id': 'det_3',
                'page': 1,
                'bbox': [100.0, 200.0, 150.0, 25.0],
                'value': '9876543210',
                'type': 'identifier_candidate',
                'risk': 'LOW',
                'confidence': 'low'
            }
        ]
        deduped = self.scanner._deduplicate_detections(detections)
        # All three overlap the exact same region; must deduplicate to exactly 1 item
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]['type'], 'phone')
        self.assertEqual(deduped[0]['risk'], 'MEDIUM')

    # 13. Toolbar layout and Style control CSS alignment rules
    def test_13_toolbar_style_alignment_css(self):
        css_path = os.path.join(BASE_DIR, 'static', 'css', 'style.css')
        with open(css_path, 'r', encoding='utf-8') as f:
            css = f.read()

        # Verify .style-selector-container uses inline-flex with height: 36px and flex-shrink: 0
        self.assertIn('.style-selector-container', css)
        self.assertIn('height: 36px', css)
        self.assertIn('flex-shrink: 0', css)

        # Verify .style-selector-label has white-space: nowrap and inline-flex alignment
        self.assertIn('.style-selector-label', css)
        self.assertIn('white-space: nowrap', css)

        # Verify responsive media query uses 1480px breakpoint for spacious desktop wrapping
        self.assertIn('@media (max-width: 1480px)', css)

if __name__ == '__main__':
    unittest.main()
