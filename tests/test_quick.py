import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.scanner import DocumentScanner
from core.cleanup import SessionManager

session_id = "test_session_01"
s_dir = SessionManager.get_session_upload_dir(session_id)
scanner = DocumentScanner()

print("--- Testing PDF Scan (medical_invoice.pdf) ---")
pdf_path = os.path.join(BASE_DIR, "samples", "medical_invoice.pdf")
res = scanner.scan_file(pdf_path, s_dir)

print("File:", res["file_name"])
print("Is PDF:", res["is_pdf"])
print("Risk Level:", res["risk_summary"]["level"], "Score:", res["risk_summary"]["score"])
print("Total Detections:", len(res["detections"]))
for d in res["detections"]:
    print(f"  [{d['risk']}] {d['label']}: {d['masked']} -> Box: {d.get('bbox')}")

print("\n--- Testing Image QR Scan (aadhaar_pan_sample.png) ---")
img_path = os.path.join(BASE_DIR, "samples", "aadhaar_pan_sample.png")
res_img = scanner.scan_file(img_path, s_dir)
print("File:", res_img["file_name"])
print("Risk Level:", res_img["risk_summary"]["level"])
print("Total Detections:", len(res_img["detections"]))
for d in res_img["detections"]:
    print(f"  [{d['risk']}] {d['label']}: {d['masked']} -> Box: {d.get('bbox')}")
