import unittest
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.regex_detector import (
    validate_verhoeff, 
    generate_verhoeff_checksum, 
    validate_luhn, 
    SensitiveDetector
)
from core.qr_detector import QRDetector
from core.risk_assessor import RiskAssessor

class TestSensitiveDetector(unittest.TestCase):

    def setUp(self):
        self.detector = SensitiveDetector()
        self.qr_detector = QRDetector()

    def test_verhoeff_aadhaar_validation(self):
        # Generate valid 12-digit Aadhaar using 11 digits
        valid_aadhaar = generate_verhoeff_checksum("23456789012")
        self.assertTrue(validate_verhoeff(valid_aadhaar))
        self.assertTrue(validate_verhoeff(f"{valid_aadhaar[:4]} {valid_aadhaar[4:8]} {valid_aadhaar[8:]}"))

        # Invalid checksum digit
        corrupt_aadhaar = valid_aadhaar[:-1] + str((int(valid_aadhaar[-1]) + 1) % 10)
        self.assertFalse(validate_verhoeff(corrupt_aadhaar))

        # Aadhaar starting with 0 or 1 is invalid
        self.assertFalse(validate_verhoeff("012345678901"))
        self.assertFalse(validate_verhoeff("123456789012"))

    def test_luhn_credit_card_validation(self):
        # Valid test Visa number
        valid_visa = "4532 0156 7890 1239"
        self.assertTrue(validate_luhn(valid_visa))

        # Corrupted digit fails Luhn
        invalid_visa = "4532 0156 7890 1234"
        self.assertFalse(validate_luhn(invalid_visa))

    def test_pan_detection(self):
        sample_text = "Taxpayer PAN number is ABCDE1234F registered in New Delhi."
        results = self.detector.scan_text(sample_text)
        pan_matches = [r for r in results if r['type'] == 'pan']
        self.assertEqual(len(pan_matches), 1)
        self.assertEqual(pan_matches[0]['value'], 'ABCDE1234F')
        self.assertEqual(pan_matches[0]['risk'], 'HIGH')

    def test_pii_entities_extraction(self):
        text = (
            "Contact user at security-admin@example.com or call +1 555-019-2834. "
            "Server IP: 192.168.1.100. "
            "AWS Token: AKIAIOSFODNN7EXAMPLE. "
            "SSN: 123-45-6789."
        )
        results = self.detector.scan_text(text)
        types_found = {r['type'] for r in results}

        self.assertIn('email', types_found)
        self.assertIn('phone', types_found)
        self.assertIn('ip_address', types_found)
        self.assertIn('api_key', types_found)
        self.assertIn('ssn', types_found)

    def test_qr_payload_inspection(self):
        # UPI Payload
        upi_payload = "upi://pay?pa=merchant@okaxis&pn=SuperStore&am=150.00"
        analysis = self.qr_detector.analyze_payload(upi_payload)
        self.assertEqual(analysis['payload_type'], 'upi')
        self.assertEqual(analysis['risk'], 'HIGH')
        self.assertIn('merchant@okaxis', analysis['preview'])

        # vCard Payload
        vcard = "BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nTEL:+15551234567\nEMAIL:john@example.com\nEND:VCARD"
        vcard_analysis = self.qr_detector.analyze_payload(vcard)
        self.assertEqual(vcard_analysis['payload_type'], 'vcard')
        self.assertEqual(vcard_analysis['risk'], 'HIGH')

        # Wi-Fi Payload
        wifi = "WIFI:S:HomeNet;T:WPA;P:SecretPass123;;"
        wifi_analysis = self.qr_detector.analyze_payload(wifi)
        self.assertEqual(wifi_analysis['payload_type'], 'wifi')
        self.assertEqual(wifi_analysis['risk'], 'HIGH')

    def test_risk_assessor_scoring(self):
        critical_detections = [
            {'risk': 'CRITICAL', 'category': 'Identity Document'},
            {'risk': 'HIGH', 'category': 'Financial Identity'},
            {'risk': 'LOW', 'category': 'Contact Information'}
        ]
        assessment = RiskAssessor.assess(critical_detections)
        self.assertEqual(assessment['level'], 'CRITICAL')
        self.assertGreaterEqual(assessment['score'], 55)

        clean_assessment = RiskAssessor.assess([])
        self.assertEqual(clean_assessment['level'], 'CLEAN')
        self.assertEqual(clean_assessment['score'], 0)

if __name__ == '__main__':
    unittest.main()
