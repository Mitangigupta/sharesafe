import unittest
import os
import sys
import json
import uuid
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.privacy_assistant import PrivacyAssistant
from core.scanner import DocumentScanner
from app import app, SessionManager

class TestPrivacyAssistant(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_01_empty_detections_clean_summary(self):
        """Clean document produces friendly non-alarmist summary and empty recommendations."""
        res = PrivacyAssistant.generate_recommendations([], sharing_context='academic', file_name='CleanDoc.pdf')
        self.assertEqual(len(res['recommendations']), 0)
        self.assertEqual(res['stats']['total'], 0)
        self.assertIn('No sensitive items or automated security risks were identified', res['summary'])

    def test_02_government_id_high_priority_recommendation(self):
        """Confirmed government ID receives HIGH_PRIORITY and REDACT recommendation."""
        detections = [{
            'id': 'det_aadhaar_01',
            'type': 'aadhaar',
            'label': 'Aadhaar Card Number',
            'value': '2345 6789 0123',
            'masked': '•••• •••• 0123',
            'category': 'Government Identification',
            'risk': 'CRITICAL',
            'confidence': 'high',
            'page': 1,
            'bbox': [100, 100, 150, 30]
        }]
        res = PrivacyAssistant.generate_recommendations(detections, sharing_context='academic')
        self.assertEqual(len(res['recommendations']), 1)
        rec = res['recommendations'][0]
        self.assertEqual(rec['priority'], 'HIGH_PRIORITY')
        self.assertEqual(rec['action'], 'REDACT')
        self.assertIn('statutory privacy risk', rec['risk_description'].lower())
        self.assertEqual(rec['confidence_label'], 'Confirmed Match')

    def test_03_uncertain_ocr_finding_recommends_review(self):
        """Unverified/uncertain findings receive REVIEW recommendation instead of automatic alarm."""
        detections = [{
            'id': 'det_cand_01',
            'type': 'identifier_candidate',
            'label': 'Identifier Candidate',
            'value': '890123456789',
            'masked': '••••••••6789',
            'category': 'General Identifier',
            'risk': 'MEDIUM',
            'confidence': 'low',
            'review_required': True,
            'page': 1,
            'bbox': [50, 50, 120, 25]
        }]
        res = PrivacyAssistant.generate_recommendations(detections, sharing_context='academic')
        self.assertEqual(len(res['recommendations']), 1)
        rec = res['recommendations'][0]
        self.assertEqual(rec['priority'], 'REVIEW')
        self.assertEqual(rec['action'], 'REVIEW')
        self.assertIn('Uncertain', rec['confidence_label'])
        self.assertIn('Inspect Region', rec['action_label'])

    def test_04_phone_and_email_context_awareness(self):
        """Phone and email recommendations adapt based on public vs academic context."""
        dets = [
            {
                'id': 'det_email_01',
                'type': 'email',
                'label': 'Email Address',
                'value': 'alice@example.com',
                'masked': 'a•••e@example.com',
                'category': 'Contact Details',
                'risk': 'LOW',
                'page': 1,
                'bbox': [10, 10, 80, 20]
            },
            {
                'id': 'det_phone_01',
                'type': 'phone',
                'label': 'Phone Number',
                'value': '+91 9876543210',
                'masked': '+91 ••••• •3210',
                'category': 'Contact Details',
                'risk': 'MEDIUM',
                'page': 1,
                'bbox': [10, 40, 90, 20]
            }
        ]
        # Academic / Private context: Review recommended
        acad_res = PrivacyAssistant.generate_recommendations(dets, sharing_context='academic')
        email_rec_acad = next(r for r in acad_res['recommendations'] if r['finding_id'] == 'det_email_01')
        self.assertEqual(email_rec_acad['priority'], 'REVIEW')

        # Public context: Email & Phone become HIGH_PRIORITY
        pub_res = PrivacyAssistant.generate_recommendations(dets, sharing_context='public')
        email_rec_pub = next(r for r in pub_res['recommendations'] if r['finding_id'] == 'det_email_01')
        phone_rec_pub = next(r for r in pub_res['recommendations'] if r['finding_id'] == 'det_phone_01')
        self.assertEqual(email_rec_pub['priority'], 'HIGH_PRIORITY')
        self.assertEqual(phone_rec_pub['priority'], 'HIGH_PRIORITY')

    def test_05_qr_code_with_safe_url_is_informational(self):
        """Standard public website QR code is classified as INFORMATIONAL with LEAVE action."""
        detections = [{
            'id': 'det_qr_01',
            'type': 'qr_code',
            'label': 'QR Code (Web URL)',
            'value': 'https://wikipedia.org/wiki/Privacy',
            'masked': 'https://wikipedia.org/...',
            'category': 'Digital Code',
            'payload_type': 'url',
            'risk': 'LOW',
            'page': 1,
            'bbox': [200, 200, 100, 100]
        }]
        res = PrivacyAssistant.generate_recommendations(detections)
        self.assertEqual(len(res['recommendations']), 1)
        rec = res['recommendations'][0]
        self.assertEqual(rec['priority'], 'INFORMATIONAL')
        self.assertEqual(rec['action'], 'LEAVE')
        self.assertIn('Low privacy risk', rec['risk_description'])

    def test_06_qr_code_with_sensitive_upi_is_high_priority(self):
        """UPI Payment or sensitive QR payload receives HIGH_PRIORITY and REDACT."""
        detections = [{
            'id': 'det_qr_upi',
            'type': 'qr_code',
            'label': 'QR Code (UPI Payment)',
            'value': 'upi://pay?pa=merchant@upi&pn=Test&am=500',
            'masked': 'upi://pay?pa=m•••@upi',
            'category': 'Digital Code',
            'payload_type': 'upi',
            'risk': 'HIGH',
            'page': 1,
            'bbox': [200, 200, 100, 100]
        }]
        res = PrivacyAssistant.generate_recommendations(detections)
        rec = res['recommendations'][0]
        self.assertEqual(rec['priority'], 'HIGH_PRIORITY')
        self.assertEqual(rec['action'], 'REDACT')

    def test_07_multi_page_mapping(self):
        """Findings on multiple pages retain their respective page associations."""
        detections = [
            {'id': 'p1_id', 'type': 'pan', 'label': 'PAN Card', 'value': 'ABCDE1234F', 'page': 1, 'bbox': [10, 10, 50, 20], 'risk': 'CRITICAL'},
            {'id': 'p2_id', 'type': 'phone', 'label': 'Phone', 'value': '9876543210', 'page': 2, 'bbox': [20, 20, 50, 20], 'risk': 'MEDIUM'}
        ]
        res = PrivacyAssistant.generate_recommendations(detections, is_pdf=True, page_count=2)
        p1_rec = next(r for r in res['recommendations'] if r['finding_id'] == 'p1_id')
        p2_rec = next(r for r in res['recommendations'] if r['finding_id'] == 'p2_id')
        self.assertEqual(p1_rec['page'], 1)
        self.assertEqual(p2_rec['page'], 2)

    def test_08_api_decision_accept_and_dismiss(self):
        """Backend endpoint /api/assistant/decision updates decision state without breaking session data."""
        session_id = uuid.uuid4().hex
        upload_dir = SessionManager.get_session_upload_dir(session_id)
        os.makedirs(upload_dir, exist_ok=True)

        session_info = {
            'session_id': session_id,
            'file_name': 'sample.png',
            'is_pdf': False,
            'page_count': 1,
            'sharing_context': 'academic',
            'detections': [{
                'id': 'det_01',
                'type': 'pan',
                'label': 'PAN Card',
                'value': 'ABCDE1234F',
                'page': 1,
                'bbox': [10, 10, 50, 20],
                'risk': 'CRITICAL'
            }],
            'risk_summary': {'score': 70, 'level': 'HIGH'},
            'metadata': {'metadata_count': 0}
        }
        with open(os.path.join(upload_dir, 'session_info.json'), 'w', encoding='utf-8') as f:
            json.dump(session_info, f)

        # Accept recommendation
        resp = self.client.post(f'/api/assistant/decision/{session_id}', json={
            'recommendation_id': 'rec_det_01',
            'decision': 'accept'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['stats']['accepted'], 1)
        self.assertEqual(data['stats']['pending'], 0)

        # Dismiss recommendation
        resp2 = self.client.post(f'/api/assistant/decision/{session_id}', json={
            'recommendation_id': 'rec_det_01',
            'decision': 'dismiss'
        })
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertEqual(data2['stats']['dismissed'], 1)
        self.assertEqual(data2['stats']['accepted'], 0)

    def test_09_api_decision_accept_all_high(self):
        """accept_all_high decision accepts all high priority recommendations at once."""
        session_id = uuid.uuid4().hex
        upload_dir = SessionManager.get_session_upload_dir(session_id)
        os.makedirs(upload_dir, exist_ok=True)

        session_info = {
            'session_id': session_id,
            'file_name': 'sample2.png',
            'is_pdf': False,
            'page_count': 1,
            'sharing_context': 'academic',
            'detections': [
                {'id': 'det_high_1', 'type': 'pan', 'label': 'PAN Card', 'value': 'ABCDE1234F', 'page': 1, 'bbox': [10, 10, 50, 20], 'risk': 'CRITICAL'},
                {'id': 'det_high_2', 'type': 'ssn', 'label': 'SSN', 'value': '123-45-6789', 'page': 1, 'bbox': [10, 40, 50, 20], 'risk': 'CRITICAL'},
                {'id': 'det_low_1', 'type': 'email', 'label': 'Email', 'value': 'test@example.com', 'page': 1, 'bbox': [10, 70, 50, 20], 'risk': 'LOW'}
            ],
            'risk_summary': {'score': 85, 'level': 'CRITICAL'},
            'metadata': {'metadata_count': 0}
        }
        with open(os.path.join(upload_dir, 'session_info.json'), 'w', encoding='utf-8') as f:
            json.dump(session_info, f)

        resp = self.client.post(f'/api/assistant/decision/{session_id}', json={
            'decision': 'accept_all_high'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['stats']['accepted'], 2)
        self.assertEqual(data['stats']['pending'], 1)

    def test_10_workbench_page_renders_assistant_tab(self):
        """Workbench route successfully includes assistant tab button and pane."""
        session_id = uuid.uuid4().hex
        upload_dir = SessionManager.get_session_upload_dir(session_id)
        os.makedirs(upload_dir, exist_ok=True)

        # Place a dummy image so page 1 preview works
        from PIL import Image
        img = Image.new('RGB', (200, 200), color='white')
        img.save(os.path.join(upload_dir, 'page_1.png'))
        img.save(os.path.join(upload_dir, 'doc.png'))

        session_info = {
            'session_id': session_id,
            'file_name': 'doc.png',
            'is_pdf': False,
            'page_count': 1,
            'sharing_context': 'academic',
            'detections': [],
            'risk_summary': {'score': 0, 'level': 'LOW', 'recommendation': 'Clean document'},
            'metadata': {'metadata_count': 0},
            'pages': [{'page_num': 1, 'width': 200, 'height': 200}]
        }
        with open(os.path.join(upload_dir, 'session_info.json'), 'w', encoding='utf-8') as f:
            json.dump(session_info, f)

        resp = self.client.get(f'/workbench/{session_id}')
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn('tabAssistantBtn', html)
        self.assertIn('paneAssistant', html)
        self.assertIn('Privacy Assistant', html)

if __name__ == '__main__':
    unittest.main()
