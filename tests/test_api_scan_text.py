import unittest
import json
from app import app

class TestApiScanText(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_health_endpoint(self):
        """Verify GET /api/health returns online status and CORS headers."""
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get('status'), 'online')
        self.assertEqual(data.get('service'), 'ShareSafe Core Engine')
        self.assertIn('ocr_available', data)
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')

    def test_health_preflight_options(self):
        """Verify OPTIONS /api/health preflight handles CORS gracefully."""
        response = self.client.open('/api/health', method='OPTIONS')
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')

    def test_scan_text_preflight_options(self):
        """Verify OPTIONS /api/scan-text preflight returns 204 with CORS headers."""
        response = self.client.open('/api/scan-text', method='OPTIONS')
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')

    def test_scan_text_clean_content(self):
        """Verify clean text returns zero findings and CLEAN risk status."""
        payload = {
            'text': 'The quarterly cybersecurity research workshop starts at 10 AM in Room 402.',
            'sharing_context': 'academic'
        }
        response = self.client.post(
            '/api/scan-text',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get('success'))
        self.assertEqual(data.get('total_findings'), 0)
        self.assertEqual(data.get('risk_summary', {}).get('level'), 'CLEAN')
        self.assertTrue(data.get('risk_summary', {}).get('can_share_safely'))
        self.assertEqual(data.get('masked_text'), payload['text'])

    def test_scan_text_pii_detection_and_masking(self):
        """Verify detection of Aadhaar (Verhoeff), Credit Card (Luhn), and Phone with masking."""
        text = "Resident 2345 6789 0123 card 4111 1111 1111 1111 phone +91 98765 43210"
        payload = {
            'text': text,
            'sharing_context': 'professional'
        }
        response = self.client.post(
            '/api/scan-text',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get('success'))
        self.assertGreaterEqual(data.get('total_findings'), 3)

        detected_types = {d['type'] for d in data.get('detections', [])}
        self.assertIn('aadhaar', detected_types)
        self.assertIn('credit_card', detected_types)
        self.assertIn('phone', detected_types)

        # Confirm critical risk assigned
        self.assertEqual(data.get('risk_summary', {}).get('level'), 'CRITICAL')
        self.assertFalse(data.get('risk_summary', {}).get('can_share_safely'))

        # Confirm masked text does not contain raw sensitive numbers
        masked = data.get('masked_text', '')
        self.assertNotIn('2345 6789 0123', masked)
        self.assertNotIn('4111 1111 1111 1111', masked)
        self.assertIn('XXXX-XXXX-0123', masked)
        self.assertIn('****-****-****-1111', masked)

        # Confirm assistant recommendations generated
        asst = data.get('assistant', {})
        self.assertIn('recommendations', asst)
        self.assertGreater(len(asst['recommendations']), 0)

    def test_scan_text_invalid_input(self):
        """Verify invalid non-string input returns 400 error."""
        response = self.client.post(
            '/api/scan-text',
            data=json.dumps({'text': 12345}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn('error', data)

    def test_scan_text_payload_too_large(self):
        """Verify text payloads exceeding 500 KB are rejected."""
        huge_text = "A" * 500001
        response = self.client.post(
            '/api/scan-text',
            data=json.dumps({'text': huge_text}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn('exceeds maximum allowed size', data.get('error', ''))

if __name__ == '__main__':
    unittest.main()
