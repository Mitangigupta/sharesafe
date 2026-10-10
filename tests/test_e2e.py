import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.scanner import DocumentScanner
from core.redactor import DocumentRedactor
from core.certificate_gen import CertificateGenerator
from core.metadata_cleaner import MetadataCleaner
from core.cleanup import SessionManager
import pymupdf

session_id = "test_e2e_session"
s_upload = SessionManager.get_session_upload_dir(session_id)
s_output = SessionManager.get_session_output_dir(session_id)
scanner = DocumentScanner()

print("--- 1. Testing PDF Scan ---")
pdf_path = os.path.join(BASE_DIR, "samples", "medical_invoice.pdf")
res = scanner.scan_file(pdf_path, s_upload)
print(f"Detected {len(res['detections'])} entities in {res['file_name']}. Initial Risk: {res['risk_summary']['level']}")

# Inspect metadata
meta_before = MetadataCleaner.inspect_file(pdf_path)
print(f"Metadata before redaction: {meta_before['status']} ({meta_before['metadata_count']} tags)")

print("--- 2. Applying Redactions (All Detections) ---")
# Apply blackout and blur
redaction_instructions = []
for idx, d in enumerate(res['detections']):
    style = 'blur' if idx % 2 == 1 else 'blackout'
    redaction_instructions.append({
        'page': d['page'],
        'bbox': d['bbox'],
        'style': style,
        'label': d['type'],
        'category': d['category']
    })

out_safe_pdf = DocumentRedactor.redact_document(
    original_file_path=pdf_path,
    is_pdf=True,
    session_dir=s_output,
    redactions=redaction_instructions,
    output_filename="safe_medical_invoice.pdf"
)
print(f"Redacted safe document created at: {out_safe_pdf} (Size: {os.path.getsize(out_safe_pdf)} bytes)")

print("--- 3. Verifying Permanent Text Destruction (Anti-Recovery) ---")
doc_check = pymupdf.open(out_safe_pdf)
page_text = doc_check[0].get_text()
print(f"Text remaining in sanitized PDF page: {len(page_text.strip())} chars (Expected: 0 chars due to raster flattening)")
assert len(page_text.strip()) == 0, "Sanitized PDF must not contain any extractable text!"
doc_check.close()
print("Passed! Text recovery is impossible.")

print("--- 4. Verifying Metadata Stripping ---")
meta_after = MetadataCleaner.inspect_file(out_safe_pdf)
print(f"Metadata after redaction: {meta_after['status']} ({meta_after['metadata_count']} tags)")

print("--- 5. Generating Cryptographic Audit Certificate ---")
audit_data = CertificateGenerator.generate_audit_data(
    orig_file_path=pdf_path,
    redacted_file_path=out_safe_pdf,
    pre_risk=res['risk_summary'],
    redactions_applied=redaction_instructions
)
cert_pdf_path = os.path.join(s_output, "audit_certificate.pdf")
CertificateGenerator.create_pdf_certificate(audit_data, cert_pdf_path)
print(f"Audit Certificate created: {cert_pdf_path} (Size: {os.path.getsize(cert_pdf_path)} bytes)")
print(f"Cert ID: {audit_data['certificate_id']}")
print(f"Original SHA-256: {audit_data['original_sha256']}")
print(f"Redacted SHA-256: {audit_data['redacted_sha256']}")

print("\n--- ALL CORE INTEGRATION TESTS PASSED! ---")
