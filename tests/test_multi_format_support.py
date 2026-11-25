import csv
import io
import json
import os
import sys
import tempfile
import unittest

import docx
import openpyxl
import pptx
from PIL import Image, ImageDraw

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from core.cleanup import SessionManager


class TestMultiFormatSupport(unittest.TestCase):
    """End-to-end tests for Upload -> Extraction -> Threat Detection -> Risk Score -> Redaction -> Download."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.created_sessions = []

    def tearDown(self):
        for sid in self.created_sessions:
            try:
                SessionManager.purge_session(sid)
            except Exception:
                pass
        self.tmp_dir.cleanup()

    def _run_e2e_flow(self, file_path: str, filename: str, expect_detections: bool = True):
        # 1. Upload
        with open(file_path, 'rb') as f:
            resp = self.client.post(
                '/upload',
                data={'file': (f, filename), 'sharing_context': 'public'},
                content_type='multipart/form-data'
            )
        self.assertEqual(resp.status_code, 200, f"Upload failed for {filename}: {resp.data}")
        up_data = json.loads(resp.data)
        self.assertTrue(up_data['success'])
        sid = up_data['session_id']
        self.created_sessions.append(sid)

        # 2. Verify session info (extraction, detections, risk score)
        upload_dir = SessionManager.get_session_upload_dir(sid)
        with open(os.path.join(upload_dir, 'session_info.json'), 'r', encoding='utf-8') as f:
            s_info = json.load(f)

        self.assertGreaterEqual(len(s_info['pages']), 1)
        detections = s_info['detections']
        if expect_detections:
            self.assertGreater(len(detections), 0, f"Expected detections for {filename}")
            self.assertGreater(s_info['risk_summary']['score'], 0)
            self.assertNotEqual(s_info['risk_summary']['level'], 'CLEAN')

        # 3. Redact
        det_ids = [d['id'] for d in detections]
        redact_resp = self.client.post(
            f'/api/redact/{sid}',
            json={'selected_detection_ids': det_ids, 'default_style': 'blackout'}
        )
        self.assertEqual(redact_resp.status_code, 200, f"Redact failed for {filename}: {redact_resp.data}")
        redact_data = json.loads(redact_resp.data)
        self.assertTrue(redact_data['success'])
        self.assertTrue(redact_data['download_filename'].startswith('safe_'))
        self.assertEqual(
            os.path.splitext(redact_data['download_filename'])[1].lower(),
            os.path.splitext(filename)[1].lower()
        )

        # 4. Download
        dl_resp = self.client.get(f'/download/{sid}/document')
        self.assertEqual(dl_resp.status_code, 200)
        dl_bytes = dl_resp.data
        dl_resp.close()
        self.assertGreater(len(dl_bytes), 0)
        return dl_bytes, detections

    def test_docx_e2e(self):
        path = os.path.join(self.tmp_dir.name, 'sample.docx')
        doc = docx.Document()
        doc.core_properties.author = 'alice.admin@corp-demo.io'
        doc.core_properties.comments = 'Internal key AKIAIOSFODNN7EXAMPLE'
        doc.add_paragraph('Contact alice.admin@corp-demo.io or call +1 415-555-0199.')
        table = doc.add_table(rows=1, cols=2)
        table.cell(0, 0).text = 'SSN'
        table.cell(0, 1).text = '123-45-6789'
        doc.save(path)

        out_bytes, _ = self._run_e2e_flow(path, 'sample.docx')
        out_doc = docx.Document(io.BytesIO(out_bytes))
        full_text = "\n".join(p.text for p in out_doc.paragraphs) + "\n" + "\n".join(
            c.text for t in out_doc.tables for r in t.rows for c in r.cells
        )
        self.assertNotIn('alice.admin@corp-demo.io', full_text)
        self.assertNotIn('123-45-6789', full_text)
        self.assertEqual(out_doc.core_properties.author, '')

    def test_pptx_e2e(self):
        path = os.path.join(self.tmp_dir.name, 'sample.pptx')
        prs = pptx.Presentation()
        prs.core_properties.author = 'bob.presenter@corp-demo.io'
        slide = prs.slides.add_slide(prs.slide_layouts[1])
        slide.shapes.title.text = 'Q4 Secrets'
        slide.placeholders[1].text = 'AWS Key: AKIAIOSFODNN7EXAMPLE\nEmail: bob.presenter@corp-demo.io'
        slide.notes_slide.notes_text_frame.text = 'Backup SSN: 123-45-6789'
        prs.save(path)

        out_bytes, _ = self._run_e2e_flow(path, 'sample.pptx')
        out_prs = pptx.Presentation(io.BytesIO(out_bytes))
        slide_texts = []
        for s in out_prs.slides:
            for sh in s.shapes:
                if sh.has_text_frame:
                    slide_texts.append(sh.text_frame.text)
            if s.has_notes_slide:
                slide_texts.append(s.notes_slide.notes_text_frame.text)
        joined = "\n".join(slide_texts)
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', joined)
        self.assertNotIn('123-45-6789', joined)
        self.assertEqual(out_prs.core_properties.author, '')

    def test_xlsx_e2e(self):
        path = os.path.join(self.tmp_dir.name, 'sample.xlsx')
        wb = openpyxl.Workbook()
        wb.properties.creator = 'finance@corp-demo.io'
        ws = wb.active
        ws.title = 'Users'
        ws['A1'] = 'Email'
        ws['B1'] = 'SSN'
        ws['A2'] = 'jane.doe@example.org'
        ws['B2'] = '123-45-6789'
        wb.save(path)

        out_bytes, _ = self._run_e2e_flow(path, 'sample.xlsx')
        out_wb = openpyxl.load_workbook(io.BytesIO(out_bytes))
        out_ws = out_wb['Users']
        self.assertNotIn('jane.doe@example.org', str(out_ws['A2'].value))
        self.assertNotIn('123-45-6789', str(out_ws['B2'].value))
        self.assertFalse(out_wb.properties.creator)
        out_wb.close()

    def test_txt_e2e(self):
        path = os.path.join(self.tmp_dir.name, 'notes.txt')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('Admin email: sec@corp-demo.io\nAPI Key: AKIAIOSFODNN7EXAMPLE\n')

        out_bytes, _ = self._run_e2e_flow(path, 'notes.txt')
        text = out_bytes.decode('utf-8')
        self.assertNotIn('sec@corp-demo.io', text)
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', text)

    def test_csv_e2e(self):
        path = os.path.join(self.tmp_dir.name, 'users.csv')
        with open(path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['name', 'email', 'ssn'])
            writer.writerow(['John', 'john.csv@example.com', '123-45-6789'])

        out_bytes, _ = self._run_e2e_flow(path, 'users.csv')
        text = out_bytes.decode('utf-8')
        self.assertNotIn('john.csv@example.com', text)
        self.assertNotIn('123-45-6789', text)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], ['name', 'email', 'ssn'])

    def _create_test_image(self, ext: str) -> str:
        path = os.path.join(self.tmp_dir.name, f'sample.{ext}')
        img = Image.new('RGB', (400, 120), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.text((20, 40), 'Email: img@example.com', fill=(0, 0, 0))
        fmt = {'jpg': 'JPEG', 'jpeg': 'JPEG', 'png': 'PNG', 'webp': 'WEBP', 'bmp': 'BMP', 'tiff': 'TIFF', 'gif': 'GIF'}[ext]
        img.save(path, format=fmt)
        return path

    def test_image_formats_e2e(self):
        for ext in ('jpg', 'png', 'webp', 'bmp', 'tiff', 'gif'):
            with self.subTest(ext=ext):
                path = self._create_test_image(ext)
                self._run_e2e_flow(path, f'sample.{ext}', expect_detections=False)

    def test_auto_redact_attachment_docx(self):
        path = os.path.join(self.tmp_dir.name, 'attach.docx')
        doc = docx.Document()
        doc.add_paragraph('Confidential token AKIAIOSFODNN7EXAMPLE for dev@corp-demo.io')
        doc.save(path)

        with open(path, 'rb') as f:
            resp = self.client.post(
                '/api/auto-redact-attachment',
                data={'file': (f, 'attach.docx'), 'sharing_context': 'public'},
                content_type='multipart/form-data'
            )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data['success'])
        self.assertFalse(data['is_clean'])
        self.assertTrue(data['non_recoverable_verified'])
        self.created_sessions.append(data['session_id'])

    def test_security_and_error_handling(self):
        # 1. Unsupported extension
        resp = self.client.post(
            '/upload',
            data={'file': (io.BytesIO(b'hello'), 'malware.exe')},
            content_type='multipart/form-data'
        )
        self.assertEqual(resp.status_code, 400)

        # 2. Fake DOCX (plain text disguised as .docx)
        resp = self.client.post(
            '/upload',
            data={'file': (io.BytesIO(b'not a zip'), 'fake.docx')},
            content_type='multipart/form-data'
        )
        self.assertEqual(resp.status_code, 400)

        # 3. Binary null bytes disguised as .txt
        resp = self.client.post(
            '/upload',
            data={'file': (io.BytesIO(b'\x00\x01\x02binary'), 'fake.txt')},
            content_type='multipart/form-data'
        )
        self.assertEqual(resp.status_code, 400)

        # 4. Empty file
        resp = self.client.post(
            '/upload',
            data={'file': (io.BytesIO(b''), 'empty.csv')},
            content_type='multipart/form-data'
        )
        self.assertEqual(resp.status_code, 400)


if __name__ == '__main__':
    unittest.main()
