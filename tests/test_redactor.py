import unittest
import os
import sys
import numpy as np
import cv2
import pymupdf

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.redactor import DocumentRedactor
from core.metadata_cleaner import MetadataCleaner
from core.certificate_gen import CertificateGenerator
from core.cleanup import SessionManager

class TestRedactorAndCertificate(unittest.TestCase):

    def setUp(self):
        self.session_id = "test_unit_redactor"
        self.upload_dir = SessionManager.get_session_upload_dir(self.session_id)
        self.output_dir = SessionManager.get_session_output_dir(self.session_id)

    def tearDown(self):
        SessionManager.purge_session(self.session_id)

    def test_image_redaction_styles(self):
        # Create synthetic test image (white 200x200)
        img = np.ones((200, 200, 3), dtype=np.uint8) * 255

        redactions = [
            {'bbox': [10, 10, 50, 50], 'style': 'blackout', 'label': 'BLACK'},
            {'bbox': [70, 10, 50, 50], 'style': 'blur', 'label': 'BLUR'},
            {'bbox': [10, 70, 50, 50], 'style': 'pixelate', 'label': 'PIXEL'},
            {'bbox': [70, 70, 50, 50], 'style': 'stamp', 'label': 'SECRET'}
        ]

        result = DocumentRedactor.redact_image_np(img, redactions)
        self.assertEqual(result.shape, (200, 200, 3))

        # Check that blackout region is dark
        roi_black = result[15:45, 15:45]
        self.assertTrue(np.all(roi_black == 0))

    def test_permanent_pdf_sanitization(self):
        # Create a tiny digital PDF with sensitive text
        test_pdf_path = os.path.join(self.upload_dir, "sensitive.pdf")
        doc = pymupdf.open()
        page = doc.new_page(width=595, height=842)
        page.insert_text((50, 100), "Sensitive Aadhaar: 2345 6789 0123")
        page.insert_text((50, 150), "Confidential Visa: 4532 0156 7890 1239")
        doc.save(test_pdf_path)
        doc.close()

        # Confirm text exists before redaction
        doc_before = pymupdf.open(test_pdf_path)
        self.assertIn("Aadhaar", doc_before[0].get_text())
        doc_before.close()

        # Apply redaction
        redactions = [
            {'page': 1, 'bbox': [40, 80, 400, 40], 'style': 'blackout', 'label': 'AADHAAR'},
            {'page': 1, 'bbox': [40, 130, 400, 40], 'style': 'blur', 'label': 'VISA'}
        ]
        out_pdf_path = DocumentRedactor.redact_document(
            original_file_path=test_pdf_path,
            is_pdf=True,
            session_dir=self.output_dir,
            redactions=redactions,
            output_filename="sanitized.pdf"
        )

        # Confirm output exists
        self.assertTrue(os.path.exists(out_pdf_path))

        # VERIFY TRUE PERMANENCE: No text selectable or extractable
        doc_after = pymupdf.open(out_pdf_path)
        extracted_text = doc_after[0].get_text().strip()
        doc_after.close()

        self.assertEqual(len(extracted_text), 0, "Sanitized PDF must have zero extractable text")

    def test_cryptographic_certificate_generation(self):
        # Create two mock files
        f1 = os.path.join(self.upload_dir, "doc1.txt")
        f2 = os.path.join(self.output_dir, "doc2.txt")
        with open(f1, 'w') as f: f.write("Original secret data")
        with open(f2, 'w') as f: f.write("Sanitized clean data")

        pre_risk = {'level': 'CRITICAL', 'score': 85}
        redactions = [{'category': 'Identity Document', 'label': 'Aadhaar'}]

        audit_data = CertificateGenerator.generate_audit_data(f1, f2, pre_risk, redactions)
        self.assertTrue(audit_data['certificate_id'].startswith("CERT-SS-"))
        self.assertNotEqual(audit_data['original_sha256'], audit_data['redacted_sha256'])
        self.assertEqual(audit_data['post_risk_level'], 'CLEAN')

        cert_pdf = os.path.join(self.output_dir, "cert.pdf")
        CertificateGenerator.create_pdf_certificate(audit_data, cert_pdf)
        self.assertTrue(os.path.exists(cert_pdf))
        self.assertGreater(os.path.getsize(cert_pdf), 1000)

if __name__ == '__main__':
    unittest.main()
