import os
import uuid
import json
import shutil
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash

from config import Config
from core.scanner import DocumentScanner
from core.redactor import DocumentRedactor
from core.metadata_cleaner import MetadataCleaner
from core.certificate_gen import CertificateGenerator
from core.cleanup import SessionManager
from core.ocr_engine import ocr_engine

app = Flask(__name__)
app.config.from_object(Config)

scanner = DocumentScanner()

@app.before_request
def trigger_periodic_cleanup():
    # Purge expired sessions (older than 30 mins) lazily on incoming requests
    SessionManager.cleanup_old_sessions()

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    ocr_status = ocr_engine.get_status()
    samples = [
        {
            'id': 'aadhaar_pan',
            'name': 'Indian Identity Card (Aadhaar & PAN)',
            'desc': 'Contains Aadhaar UID, PAN number, Mobile phone, and scannable UPI QR code.',
            'type': 'PNG Image',
            'icon': 'id-card',
            'badge': 'Identity & QR'
        },
        {
            'id': 'medical_invoice',
            'name': 'Healthcare Patient Statement',
            'desc': 'Medical billing record containing Patient Email, SSN, Visa Card (Luhn), and Portal link.',
            'type': 'PDF Document',
            'icon': 'file-medical',
            'badge': 'Financial & HIPAA'
        },
        {
            'id': 'server_config',
            'name': 'Cloud Infrastructure & API Secrets',
            'desc': 'DevOps terminal environment with Internal/Public IPs, AWS Secret Keys, JWT, and Wi-Fi QR.',
            'type': 'PNG Image',
            'icon': 'terminal',
            'badge': 'Cloud & Credentials'
        }
    ]
    return render_template('index.html', ocr_status=ocr_status, samples=samples)

@app.route('/upload', methods=['POST'])
def upload_file():
    session_id = str(uuid.uuid4().hex[:12])
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    SessionManager.get_session_output_dir(session_id)  # prepare output dir

    sample_id = request.form.get('sample_id')

    if sample_id:
        # Load one of the built-in demo samples
        sample_map = {
            'aadhaar_pan': 'aadhaar_pan_sample.png',
            'medical_invoice': 'medical_invoice.pdf',
            'server_config': 'server_config.png'
        }
        if sample_id not in sample_map:
            return jsonify({'error': 'Invalid demo sample requested'}), 400

        src_sample = os.path.join(Config.SAMPLES_FOLDER, sample_map[sample_id])
        if not os.path.exists(src_sample):
            # Regenerate if missing
            from samples.generate_samples import create_sample_aadhaar_pan, create_sample_medical_pdf, create_sample_server_config
            if sample_id == 'aadhaar_pan': create_sample_aadhaar_pan()
            elif sample_id == 'medical_invoice': create_sample_medical_pdf()
            elif sample_id == 'server_config': create_sample_server_config()

        dest_filename = sample_map[sample_id]
        dest_path = os.path.join(upload_dir, dest_filename)
        shutil.copyfile(src_sample, dest_path)
        target_path = dest_path
        display_name = dest_filename

    else:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        ext = file.filename.rsplit('.', 1)[-1].lower()
        if ext not in Config.ALLOWED_EXTENSIONS:
            return jsonify({'error': f'Unsupported file extension .{ext}. Allowed: {", ".join(Config.ALLOWED_EXTENSIONS)}'}), 400

        display_name = os.path.basename(file.filename)
        safe_filename = f"upload_{uuid.uuid4().hex[:8]}.{ext}"
        target_path = os.path.join(upload_dir, safe_filename)
        file.save(target_path)

    sharing_context = request.form.get('sharing_context', 'academic').lower()
    if sharing_context not in ['academic', 'professional', 'private', 'public']:
        sharing_context = 'academic'

    # Execute Document Scan
    try:
        scan_result = scanner.scan_file(target_path, upload_dir, sharing_context=sharing_context, original_filename=display_name)
        meta_result = MetadataCleaner.inspect_file(target_path)

        # Save session metadata json
        session_info = {
            'session_id': session_id,
            'file_name': scan_result['file_name'],
            'is_pdf': scan_result['is_pdf'],
            'page_count': scan_result.get('page_count', len(scan_result.get('pages', []))),
            'sharing_context': sharing_context,
            'original_path': target_path,
            'pages': scan_result['pages'],
            'detections': scan_result['detections'],
            'risk_summary': scan_result['risk_summary'],
            'metadata': meta_result
        }

        with open(os.path.join(upload_dir, 'session_info.json'), 'w', encoding='utf-8') as f:
            json.dump(session_info, f, indent=2)

        return jsonify({
            'success': True,
            'session_id': session_id,
            'redirect_url': url_for('workbench', session_id=session_id)
        })

    except (ValueError, pymupdf.FileDataError) as e:
        SessionManager.purge_session(session_id)
        return jsonify({'error': f"Invalid or unreadable document file: {str(e)}"}), 400
    except Exception as e:
        SessionManager.purge_session(session_id)
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Failed to process document: {str(e)}"}), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'error': 'File exceeds maximum upload limit of 30 MB. Please select a smaller file.'
    }), 413

@app.route('/api/update-context/<session_id>', methods=['POST'])
def update_sharing_context(session_id):
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    if not os.path.exists(info_path):
        return jsonify({'error': 'Session expired or not found'}), 404

    with open(info_path, 'r', encoding='utf-8') as f:
        session_data = json.load(f)

    data = request.get_json() or {}
    new_context = data.get('context', 'academic').lower()
    if new_context not in ['academic', 'professional', 'private', 'public']:
        new_context = 'academic'

    from core.risk_assessor import RiskAssessor
    new_risk = RiskAssessor.assess(session_data.get('detections', []), context=new_context)
    session_data['sharing_context'] = new_context
    session_data['risk_summary'] = new_risk

    with open(info_path, 'w', encoding='utf-8') as f:
        json.dump(session_data, f, indent=2)

    return jsonify({'success': True, 'risk_summary': new_risk, 'sharing_context': new_context})

@app.route('/workbench/<session_id>')
def workbench(session_id):
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    if not os.path.exists(info_path):
        flash("Session expired or document not found. Please upload again.", "warning")
        return redirect(url_for('index'))

    with open(info_path, 'r', encoding='utf-8') as f:
        session_data = json.load(f)

    return render_template('workbench.html', session_data=session_data)

@app.route('/preview/<session_id>/<filename>')
def serve_preview(session_id, filename):
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    file_path = os.path.join(upload_dir, filename)
    if not os.path.exists(file_path):
        return "Not found", 404
    return send_file(file_path)

@app.route('/output-preview/<session_id>/<filename>')
def serve_output_preview(session_id, filename):
    output_dir = SessionManager.get_session_output_dir(session_id)
    file_path = os.path.join(output_dir, filename)
    if not os.path.exists(file_path):
        return "Not found", 404
    return send_file(file_path)

@app.route('/api/redact/<session_id>', methods=['POST'])
def apply_redaction(session_id):
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    output_dir = SessionManager.get_session_output_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    if not os.path.exists(info_path):
        return jsonify({'error': 'Session expired or invalid'}), 404

    with open(info_path, 'r', encoding='utf-8') as f:
        session_data = json.load(f)

    data = request.get_json() or {}
    selected_ids = set(data.get('selected_detection_ids', []))
    default_style = data.get('default_style', 'blackout')
    entity_styles = data.get('entity_styles', {})  # {det_id: 'blur' | 'pixelate' | etc}
    manual_redactions = data.get('manual_redactions', [])  # [{page, bbox, style, label}]

    # Combine selected detected items with styles
    active_redactions = []
    for d in session_data.get('detections', []):
        if d['id'] in selected_ids:
            item_style = entity_styles.get(d['id'], default_style)
            active_redactions.append({
                'id': d['id'],
                'page': d.get('page', 1),
                'bbox': d.get('bbox'),
                'style': item_style,
                'label': d.get('type', 'REDACTED'),
                'category': d.get('category', 'General PII')
            })

    # Add manual user-drawn boxes
    for m in manual_redactions:
        active_redactions.append({
            'id': f"manual_{uuid.uuid4().hex[:6]}",
            'page': m.get('page', 1),
            'bbox': m.get('bbox'),
            'style': m.get('style', default_style),
            'label': m.get('label', 'MANUAL'),
            'category': 'Manual Redaction'
        })

    orig_path = session_data['original_path']
    is_pdf = session_data['is_pdf']
    ext = os.path.splitext(orig_path)[1].lower()
    out_filename = f"safe_sanitized_{session_id[:8]}{ext}"

    try:
        # Perform permanent redaction and text stream flattening
        safe_output_path = DocumentRedactor.redact_document(
            original_file_path=orig_path,
            is_pdf=is_pdf,
            session_dir=output_dir,
            redactions=active_redactions,
            output_filename=out_filename
        )

        # Render preview images for the redacted document to enable before/after slider
        redacted_previews = []
        if is_pdf:
            import pymupdf
            out_doc = pymupdf.open(safe_output_path)
            for p_idx in range(len(out_doc)):
                zoom = 150 / 72
                pix = out_doc[p_idx].get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
                p_name = f"redacted_page_{p_idx + 1}.png"
                pix.save(os.path.join(output_dir, p_name))
                redacted_previews.append(f"/output-preview/{session_id}/{p_name}")
            out_doc.close()
        else:
            p_name = f"redacted_page_1.png"
            shutil.copyfile(safe_output_path, os.path.join(output_dir, p_name))
            redacted_previews.append(f"/output-preview/{session_id}/{p_name}")

        # Generate Cryptographic Audit Certificate
        audit_data = CertificateGenerator.generate_audit_data(
            orig_file_path=orig_path,
            redacted_file_path=safe_output_path,
            pre_risk=session_data['risk_summary'],
            redactions_applied=active_redactions
        )

        cert_pdf_path = os.path.join(output_dir, f"ShareSafe_Certificate_{session_id[:8]}.pdf")
        CertificateGenerator.create_pdf_certificate(audit_data, cert_pdf_path)

        cert_json_path = os.path.join(output_dir, f"ShareSafe_Audit_{session_id[:8]}.json")
        with open(cert_json_path, 'w', encoding='utf-8') as f:
            json.dump(audit_data, f, indent=2)

        return jsonify({
            'success': True,
            'redacted_previews': redacted_previews,
            'audit_data': audit_data,
            'download_document_url': url_for('download_document', session_id=session_id),
            'download_certificate_url': url_for('download_certificate', session_id=session_id),
            'download_json_url': url_for('download_audit_json', session_id=session_id)
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Redaction failed: {str(e)}"}), 500

@app.route('/download/<session_id>/document')
def download_document(session_id):
    output_dir = SessionManager.get_session_output_dir(session_id)
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    if not os.path.exists(info_path):
        return "Session expired", 404

    with open(info_path, 'r', encoding='utf-8') as f:
        session_data = json.load(f)

    orig_name = session_data['file_name']
    name_base, orig_ext = os.path.splitext(orig_name)
    target_ext = os.path.splitext(session_data.get('original_path', orig_name))[1].lower()
    safe_filename = f"safe_{name_base}{orig_ext or target_ext}"

    out_file = os.path.join(output_dir, f"safe_sanitized_{session_id[:8]}{target_ext}")
    if not os.path.exists(out_file):
        for fname in os.listdir(output_dir):
            if fname.startswith(f"safe_sanitized_{session_id[:8]}"):
                out_file = os.path.join(output_dir, fname)
                break
        else:
            return "File not generated yet", 404

    return send_file(out_file, as_attachment=True, download_name=safe_filename)

@app.route('/download/<session_id>/certificate')
def download_certificate(session_id):
    output_dir = SessionManager.get_session_output_dir(session_id)
    cert_pdf = os.path.join(output_dir, f"ShareSafe_Certificate_{session_id[:8]}.pdf")
    if not os.path.exists(cert_pdf):
        return "Certificate not found", 404
    return send_file(cert_pdf, as_attachment=True, download_name=f"ShareSafe_Audit_Certificate_{session_id[:8]}.pdf")

@app.route('/download/<session_id>/audit-json')
def download_audit_json(session_id):
    output_dir = SessionManager.get_session_output_dir(session_id)
    cert_json = os.path.join(output_dir, f"ShareSafe_Audit_{session_id[:8]}.json")
    if not os.path.exists(cert_json):
        return "Audit report not found", 404
    return send_file(cert_json, as_attachment=True, download_name=f"ShareSafe_Audit_Data_{session_id[:8]}.json")

@app.route('/api/purge/<session_id>', methods=['POST'])
def purge_session_data(session_id):
    success = SessionManager.purge_session(session_id)
    return jsonify({'success': success, 'message': 'All session files completely wiped from disk.'})

@app.route('/api/ocr-status')
def get_ocr_status():
    return jsonify(ocr_engine.get_status())

@app.route('/api/settings/ocr-path', methods=['POST'])
def set_ocr_path():
    data = request.get_json() or {}
    path = data.get('path', '').strip()
    success, msg = ocr_engine.set_tesseract_path(path)
    return jsonify({'success': success, 'message': msg})

if __name__ == '__main__':
    print("================================================================")
    print(" ShareSafe - Zero-Leak PII & QR Privacy Redaction Server Running")
    print(" Access at: http://127.0.0.1:5000")
    print("================================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
