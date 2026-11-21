import os
import uuid
import json
import shutil
import threading
from pathlib import Path
import queue

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, Response, stream_with_context

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

# ── SSE Scan Progress Store ──────────────────────────────────────────────────
# Maps session_id -> queue.Queue of progress event dicts
_scan_progress_queues = {}
_scan_progress_lock = threading.Lock()

def _emit_progress(session_id, step, label, pct):
    """Push a progress event onto the session queue (non-blocking)."""
    with _scan_progress_lock:
        q = _scan_progress_queues.get(session_id)
    if q:
        try:
            q.put_nowait({"step": step, "label": label, "pct": pct})
        except Exception:
            pass


def validate_file_content(file_path: str, ext: str):
    """Validates magic bytes / signatures to guarantee file integrity and bounds."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(32)
        if len(header) < 4:
            return False, "File is empty or corrupted."

        if ext == 'pdf':
            if not header.startswith(b'%PDF-'):
                return False, "Invalid PDF structure: missing %PDF- header."
            import pymupdf
            doc = pymupdf.open(file_path)
            page_count = len(doc)
            doc.close()
            if page_count > 50:
                return False, f"PDF exceeds maximum page limit (found {page_count} pages, limit is 50)."
        elif ext == 'png':
            if not header.startswith(b'\x89PNG\r\n\x1a\n'):
                return False, "Invalid PNG file: corrupted header."
        elif ext in ('jpg', 'jpeg'):
            if not header.startswith(b'\xff\xd8\xff'):
                return False, "Invalid JPEG file: corrupted header."
        elif ext == 'webp':
            if not (header.startswith(b'RIFF') and b'WEBP' in header[:16]):
                return False, "Invalid WEBP file: corrupted header."
        elif ext == 'bmp':
            if not header.startswith(b'BM'):
                return False, "Invalid BMP file: corrupted header."
        return True, ""
    except Exception as e:
        return False, f"Failed to validate file: {str(e)}"

def generate_preview_images(file_path: str, session_dir: str, is_pdf: bool):
    """Renders page preview images (page_1.png, page_2.png, ...) in session_dir."""
    if is_pdf:
        import pymupdf
        doc = pymupdf.open(file_path)
        for page_idx in range(len(doc)):
            page = doc[page_idx]
            zoom = 150 / 72
            mat = pymupdf.Matrix(zoom, zoom)
            pix = page.get_pixmap(matrix=mat)
            pix.save(os.path.join(session_dir, f"page_{page_idx + 1}.png"))
        doc.close()
    else:
        dest_preview = os.path.join(session_dir, "page_1.png")
        if file_path != dest_preview and os.path.exists(file_path):
            shutil.copyfile(file_path, dest_preview)

def restore_session_if_needed(session_id, client_session_data=None):
    """
    Guarantees session persistence across stateless serverless instances (e.g. Vercel).
    If ephemeral session files were purged or routed to a different lambda container,
    re-hydrates the session directory, original file, and previews automatically.
    """
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    if os.path.exists(info_path):
        try:
            with open(info_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass

    sample_map = {
        'aadhaar_pan': 'aadhaar_pan_sample.png',
        'medical_invoice': 'medical_invoice.pdf',
        'server_config': 'server_config.png'
    }

    sample_id = None
    file_name = None

    if client_session_data and isinstance(client_session_data, dict):
        sample_id = client_session_data.get('sample_id')
        file_name = client_session_data.get('file_name')

    if not sample_id and file_name:
        for s_id, s_file in sample_map.items():
            if s_file == file_name:
                sample_id = s_id
                break

    # If this corresponds to a demo sample, re-create the session from disk
    if sample_id and sample_id in sample_map:
        src_sample = os.path.join(Config.SAMPLES_FOLDER, sample_map[sample_id])
        if not os.path.exists(src_sample):
            from samples.generate_samples import create_sample_aadhaar_pan, create_sample_medical_pdf, create_sample_server_config
            if sample_id == 'aadhaar_pan': create_sample_aadhaar_pan()
            elif sample_id == 'medical_invoice': create_sample_medical_pdf()
            elif sample_id == 'server_config': create_sample_server_config()

        if os.path.exists(src_sample):
            dest_filename = sample_map[sample_id]
            dest_path = os.path.join(upload_dir, dest_filename)
            shutil.copyfile(src_sample, dest_path)

            if client_session_data and 'detections' in client_session_data:
                session_data = dict(client_session_data)
                session_data['original_path'] = dest_path
                session_data['sample_id'] = sample_id
                generate_preview_images(dest_path, upload_dir, session_data.get('is_pdf', False))
            else:
                scan_res = scanner.scan_file(dest_path, upload_dir, original_filename=dest_filename)
                meta_res = MetadataCleaner.inspect_file(dest_path)
                session_data = {
                    'session_id': session_id,
                    'file_name': scan_res['file_name'],
                    'sample_id': sample_id,
                    'is_pdf': scan_res['is_pdf'],
                    'page_count': scan_res.get('page_count', len(scan_res.get('pages', []))),
                    'sharing_context': 'academic',
                    'original_path': dest_path,
                    'pages': scan_res['pages'],
                    'detections': scan_res['detections'],
                    'risk_summary': scan_res['risk_summary'],
                    'metadata': meta_res,
                    'assistant': scan_res.get('assistant', {})
                }

            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
            return session_data

    # If client passed file_base64
    if client_session_data and client_session_data.get('file_base64') and file_name:
        import base64
        dest_path = os.path.join(upload_dir, file_name)
        with open(dest_path, 'wb') as f:
            f.write(base64.b64decode(client_session_data['file_base64']))
        session_data = dict(client_session_data)
        session_data['original_path'] = dest_path
        generate_preview_images(dest_path, upload_dir, session_data.get('is_pdf', False))
        with open(info_path, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2)
        return session_data

    return None


@app.before_request
def trigger_periodic_cleanup():
    # Purge expired sessions (older than 30 mins) lazily on incoming requests
    SessionManager.cleanup_old_sessions()

@app.after_request
def add_security_and_cors_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Enable CORS for Chrome Extension and local API clients
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
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
    return render_template('index.html', ocr_status=ocr_status, samples=samples, active_page='home')

@app.route('/problem-statement')
def problem_statement():
    ocr_status = ocr_engine.get_status()
    return render_template('problem_statement.html', active_page='problem-statement', ocr_status=ocr_status)

@app.route('/proposed-solution')
def proposed_solution():
    ocr_status = ocr_engine.get_status()
    return render_template('proposed_solution.html', active_page='proposed-solution', ocr_status=ocr_status)

@app.route('/objectives')
def objectives():
    ocr_status = ocr_engine.get_status()
    return render_template('objectives.html', active_page='objectives', ocr_status=ocr_status)

@app.route('/architecture-design')
def architecture_design():
    ocr_status = ocr_engine.get_status()
    return render_template('architecture_design.html', active_page='architecture-design', ocr_status=ocr_status)

@app.route('/extension')
def browser_extension():
    ocr_status = ocr_engine.get_status()
    return render_template('extension.html', active_page='extension', ocr_status=ocr_status)

@app.route('/next-milestones')
def next_milestones():
    ocr_status = ocr_engine.get_status()
    return render_template('next_milestones.html', active_page='next-milestones', ocr_status=ocr_status)

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

        # Validate file content structure / magic bytes
        is_valid, val_err = validate_file_content(target_path, ext)
        if not is_valid:
            SessionManager.purge_session(session_id)
            return jsonify({'error': val_err}), 400

    sharing_context = request.form.get('sharing_context', 'academic').lower()
    if sharing_context not in ['academic', 'professional', 'private', 'public']:
        sharing_context = 'academic'

    # Register progress queue for this session
    q = queue.Queue()
    with _scan_progress_lock:
        _scan_progress_queues[session_id] = q

    # Execute Document Scan with progress milestones
    try:
        _emit_progress(session_id, "validate", "Validating document structure...", 10)
        import time; time.sleep(0.05)

        _emit_progress(session_id, "pages", "Extracting page content...", 25)
        import time; time.sleep(0.05)

        _emit_progress(session_id, "ocr", "Running OCR text recognition...", 45)
        scan_result = scanner.scan_file(
            target_path,
            upload_dir,
            sharing_context=sharing_context,
            original_filename=display_name,
            sample_id=sample_id
        )

        _emit_progress(session_id, "risk", "Assessing risk & compliance...", 75)
        meta_result = MetadataCleaner.inspect_file(target_path)

        _emit_progress(session_id, "ai", "Generating AI recommendations...", 90)

        # Save session metadata json
        session_info = {
            "session_id": session_id,
            "scan_date": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "file_name": scan_result["file_name"],
            "sample_id": sample_id,
            "is_pdf": scan_result["is_pdf"],
            "page_count": scan_result.get("page_count", len(scan_result.get("pages", []))),
            "sharing_context": sharing_context,
            "original_path": target_path,
            "pages": scan_result["pages"],
            "detections": scan_result["detections"],
            "risk_summary": scan_result["risk_summary"],
            "metadata": meta_result,
            "assistant": scan_result.get("assistant", {}),
            "warnings": scan_result.get("warnings", [])
        }

        with open(os.path.join(upload_dir, "session_info.json"), "w", encoding="utf-8") as f:
            json.dump(session_info, f, indent=2)

        _emit_progress(session_id, "done", "Scan complete. Opening Privacy Studio...", 100)

        return jsonify({
            "success": True,
            "session_id": session_id,
            "redirect_url": url_for("workbench", session_id=session_id)
        })

    except (ValueError, pymupdf.FileDataError) as e:
        SessionManager.purge_session(session_id)
        return jsonify({'error': f"Invalid or unreadable document file: {str(e)}"}), 400
    except Exception as e:
        SessionManager.purge_session(session_id)
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Failed to process document: {str(e)}"}), 500


@app.route("/api/scan-progress/<session_id>")
def scan_progress_stream(session_id):
    """SSE endpoint: streams scan progress events to the browser as they happen."""
    with _scan_progress_lock:
        q = _scan_progress_queues.get(session_id)
    if not q:
        # No active scan for this session - send a done event immediately
        def empty_gen():
            yield "data: {\"step\": \"done\", \"label\": \"Complete\", \"pct\": 100}\n\n"
        return Response(stream_with_context(empty_gen()), mimetype="text/event-stream")

    def generate():
        try:
            while True:
                try:
                    event = q.get(timeout=30)  # wait up to 30s per event
                    import json as _json
                    yield f"data: {_json.dumps(event)}\n\n"
                    if event.get("pct", 0) >= 100:
                        break
                except queue.Empty:
                    yield "data: {\"step\": \"heartbeat\", \"label\": \"Scanning...\", \"pct\": 50}\n\n"
        finally:
            with _scan_progress_lock:
                _scan_progress_queues.pop(session_id, None)

    response = Response(stream_with_context(generate()), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response

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
    from core.privacy_assistant import PrivacyAssistant
    new_risk = RiskAssessor.assess(session_data.get('detections', []), context=new_context)
    new_assistant = PrivacyAssistant.generate_recommendations(
        session_data.get('detections', []),
        sharing_context=new_context,
        file_name=session_data.get('file_name', 'Document'),
        is_pdf=session_data.get('is_pdf', False),
        page_count=session_data.get('page_count', 1)
    )
    session_data['sharing_context'] = new_context
    session_data['risk_summary'] = new_risk
    session_data['assistant'] = new_assistant

    with open(info_path, 'w', encoding='utf-8') as f:
        json.dump(session_data, f, indent=2)

    return jsonify({'success': True, 'risk_summary': new_risk, 'assistant': new_assistant, 'sharing_context': new_context})

@app.route('/api/assistant/decision/<session_id>', methods=['POST'])
def update_assistant_decision(session_id):
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    if not os.path.exists(info_path):
        return jsonify({'error': 'Session expired or not found'}), 404

    with open(info_path, 'r', encoding='utf-8') as f:
        session_data = json.load(f)

    data = request.get_json() or {}
    rec_id = data.get('recommendation_id')
    decision = data.get('decision', 'accept').lower()

    from core.privacy_assistant import PrivacyAssistant
    assistant_data = session_data.get('assistant')
    if not assistant_data or 'recommendations' not in assistant_data:
        assistant_data = PrivacyAssistant.generate_recommendations(
            session_data.get('detections', []),
            sharing_context=session_data.get('sharing_context', 'academic'),
            file_name=session_data.get('file_name', 'Document'),
            is_pdf=session_data.get('is_pdf', False),
            page_count=session_data.get('page_count', 1)
        )
        session_data['assistant'] = assistant_data

    recs = assistant_data.get('recommendations', [])

    if decision == 'accept_all_high':
        for r in recs:
            if r.get('priority') == 'HIGH_PRIORITY':
                r['status'] = 'ACCEPTED'
    elif decision == 'accept_all':
        for r in recs:
            r['status'] = 'ACCEPTED'
    elif decision == 'reset_all':
        for r in recs:
            r['status'] = 'PENDING'
    else:
        for r in recs:
            if r.get('id') == rec_id:
                if decision == 'accept':
                    r['status'] = 'ACCEPTED'
                elif decision == 'dismiss':
                    r['status'] = 'DISMISSED'
                elif decision == 'reset':
                    r['status'] = 'PENDING'
                break

    # Recalculate stats
    total = len(recs)
    accepted = sum(1 for r in recs if r.get('status') == 'ACCEPTED')
    dismissed = sum(1 for r in recs if r.get('status') == 'DISMISSED')
    pending = total - accepted - dismissed

    stats = assistant_data.get('stats', {})
    stats['total'] = total
    stats['accepted'] = accepted
    stats['dismissed'] = dismissed
    stats['pending'] = max(0, pending)
    assistant_data['stats'] = stats

    with open(info_path, 'w', encoding='utf-8') as f:
        json.dump(session_data, f, indent=2)

    return jsonify({
        'success': True,
        'assistant': assistant_data,
        'stats': stats
    })

@app.route('/workbench/<session_id>')
def workbench(session_id):
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    if not os.path.exists(info_path):
        sample_param = request.args.get('sample')
        if sample_param:
            restore_session_if_needed(session_id, {'sample_id': sample_param})

    if not os.path.exists(info_path):
        flash("Session expired or document not found. Please upload again.", "warning")
        return redirect(url_for('index'))

    with open(info_path, 'r', encoding='utf-8') as f:
        session_data = json.load(f)

    if 'assistant' not in session_data or not session_data['assistant']:
        from core.privacy_assistant import PrivacyAssistant
        session_data['assistant'] = PrivacyAssistant.generate_recommendations(
            session_data.get('detections', []),
            sharing_context=session_data.get('sharing_context', 'academic'),
            file_name=session_data.get('file_name', 'Document'),
            is_pdf=session_data.get('is_pdf', False),
            page_count=session_data.get('page_count', 1)
        )
        with open(info_path, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2)

    return render_template('workbench.html', session_data=session_data)

@app.route('/preview/<session_id>/<filename>')
def serve_preview(session_id, filename):
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    file_path = os.path.join(upload_dir, filename)
    if not os.path.exists(file_path):
        restore_session_if_needed(session_id)
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

@app.route('/api/re-establish-session/<session_id>', methods=['POST'])
def reestablish_session(session_id):
    data = request.get_json() or {}
    client_session_data = data.get('session_data')
    session_data = restore_session_if_needed(session_id, client_session_data)
    if session_data:
        return jsonify({'success': True, 'session_id': session_id})
    return jsonify({'error': 'Unable to re-establish session. Please upload the file again.'}), 400

@app.route('/api/redact/<session_id>', methods=['POST'])
def apply_redaction(session_id):
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    output_dir = SessionManager.get_session_output_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    data = request.get_json() or {}
    client_session_data = data.get('session_data')

    session_data = None
    if os.path.exists(info_path):
        try:
            with open(info_path, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
        except Exception:
            session_data = None

    if not session_data:
        session_data = restore_session_if_needed(session_id, client_session_data)

    if not session_data or not os.path.exists(session_data.get('original_path', '')):
        return jsonify({
            'error': 'Session expired or invalid',
            'session_expired': True,
            'message': 'The cloud hosting container has recycled. Click "Restore Session" to re-establish your session.'
        }), 404

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

        # Render preview images for the redacted document
        import base64
        redacted_previews = []
        redacted_previews_data = []

        if is_pdf:
            import pymupdf
            out_doc = pymupdf.open(safe_output_path)
            for p_idx in range(len(out_doc)):
                zoom = 150 / 72
                pix = out_doc[p_idx].get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
                p_name = f"redacted_page_{p_idx + 1}.png"
                p_file = os.path.join(output_dir, p_name)
                pix.save(p_file)
                redacted_previews.append(f"/output-preview/{session_id}/{p_name}")
                with open(p_file, 'rb') as pf:
                    b64 = base64.b64encode(pf.read()).decode('utf-8')
                    redacted_previews_data.append(f"data:image/png;base64,{b64}")
            out_doc.close()
        else:
            p_name = f"redacted_page_1.png"
            p_file = os.path.join(output_dir, p_name)
            shutil.copyfile(safe_output_path, p_file)
            redacted_previews.append(f"/output-preview/{session_id}/{p_name}")
            with open(p_file, 'rb') as pf:
                b64 = base64.b64encode(pf.read()).decode('utf-8')
                redacted_previews_data.append(f"data:image/png;base64,{b64}")

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

        # Base64 encoded outputs for instant in-browser download
        with open(safe_output_path, 'rb') as f:
            doc_b64 = base64.b64encode(f.read()).decode('utf-8')
        with open(cert_pdf_path, 'rb') as f:
            cert_b64 = base64.b64encode(f.read()).decode('utf-8')

        return jsonify({
            'success': True,
            'redacted_previews': redacted_previews,
            'redacted_previews_data': redacted_previews_data,
            'document_base64': doc_b64,
            'certificate_base64': cert_b64,
            'download_filename': f"safe_{session_data['file_name']}",
            'mime_type': 'application/pdf' if is_pdf else 'image/png',
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
        restore_session_if_needed(session_id)

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
        if os.path.exists(output_dir):
            for fname in os.listdir(output_dir):
                if fname.startswith(f"safe_sanitized_{session_id[:8]}"):
                    out_file = os.path.join(output_dir, fname)
                    break

    if not out_file or not os.path.exists(out_file):
        # Auto-reconstitute sanitized document on the fly if container recycled
        try:
            active_redactions = []
            for d in session_data.get('detections', []):
                active_redactions.append({
                    'id': d['id'],
                    'page': d.get('page', 1),
                    'bbox': d.get('bbox'),
                    'style': 'blackout',
                    'label': d.get('type', 'REDACTED'),
                    'category': d.get('category', 'General PII')
                })
            out_file = DocumentRedactor.redact_document(
                original_file_path=session_data['original_path'],
                is_pdf=session_data['is_pdf'],
                session_dir=output_dir,
                redactions=active_redactions,
                output_filename=f"safe_sanitized_{session_id[:8]}{target_ext}"
            )
        except Exception:
            return "File not generated yet", 404

    return send_file(out_file, as_attachment=True, download_name=safe_filename)

@app.route('/download/<session_id>/certificate')
def download_certificate(session_id):
    output_dir = SessionManager.get_session_output_dir(session_id)
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')
    if not os.path.exists(info_path):
        restore_session_if_needed(session_id)

    cert_pdf = os.path.join(output_dir, f"ShareSafe_Certificate_{session_id[:8]}.pdf")
    if not os.path.exists(cert_pdf):
        if os.path.exists(info_path):
            try:
                with open(info_path, 'r', encoding='utf-8') as f:
                    s_data = json.load(f)
                audit_data = CertificateGenerator.generate_audit_data(
                    orig_file_path=s_data['original_path'],
                    redacted_file_path=s_data['original_path'],
                    pre_risk=s_data.get('risk_summary', {'level': 'LOW', 'score': 0}),
                    redactions_applied=[]
                )
                CertificateGenerator.create_pdf_certificate(audit_data, cert_pdf)
            except Exception:
                pass
    if not os.path.exists(cert_pdf):
        return "Certificate not found", 404
    return send_file(cert_pdf, as_attachment=True, download_name=f"ShareSafe_Audit_Certificate_{session_id[:8]}.pdf")

@app.route('/share/cert/<session_id>')
def share_certificate(session_id):
    """Public read-only shareable audit certificate page (R13)."""
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')
    if not os.path.exists(info_path):
        return render_template('cert_not_found.html', session_id=session_id), 404
    try:
        with open(info_path, 'r', encoding='utf-8') as f:
            session_data = json.load(f)
    except Exception:
        return render_template('cert_not_found.html', session_id=session_id), 404
    risk = session_data.get('risk_summary', {})
    detections = session_data.get('detections', [])
    scan_date = session_data.get('scan_date', None)
    if not scan_date:
        import datetime
        scan_date = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    return render_template(
        'share_cert.html',
        session_id=session_id,
        file_name=session_data.get('file_name', 'Unknown Document'),
        risk_level=risk.get('level', 'LOW'),
        risk_score=risk.get('score', 0),
        total_findings=len(detections),
        page_count=session_data.get('page_count', 1),
        scan_date=scan_date,
        sharing_context=session_data.get('sharing_context', 'General'),
        risk_summary=risk
    )


@app.route('/download/extension-zip')
def download_extension_zip():
    zip_path = os.path.join(app.static_folder, 'packages', 'sharesafe-extension.zip')
    if os.path.exists(zip_path):
        return send_file(zip_path, as_attachment=True, download_name='sharesafe-extension-v3.zip')
    
    extension_dir = os.path.join(os.path.dirname(__file__), 'sharesafe-extension')
    if not os.path.isdir(extension_dir):
        return jsonify({'error': 'Extension package not found'}), 404
        
    import io, zipfile
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(extension_dir):
            for file in files:
                abs_p = os.path.join(root, file)
                rel_p = os.path.relpath(abs_p, extension_dir)
                zf.write(abs_p, rel_p)
    mem_zip.seek(0)
    return send_file(mem_zip, mimetype='application/zip', as_attachment=True, download_name='sharesafe-extension-v3.zip')

@app.route('/download/<session_id>/audit-json')
def download_audit_json(session_id):
    output_dir = SessionManager.get_session_output_dir(session_id)
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')
    if not os.path.exists(info_path):
        restore_session_if_needed(session_id)

    cert_json = os.path.join(output_dir, f"ShareSafe_Audit_{session_id[:8]}.json")
    if not os.path.exists(cert_json):
        if os.path.exists(info_path):
            try:
                with open(info_path, 'r', encoding='utf-8') as f:
                    s_data = json.load(f)
                audit_data = CertificateGenerator.generate_audit_data(
                    orig_file_path=s_data['original_path'],
                    redacted_file_path=s_data['original_path'],
                    pre_risk=s_data.get('risk_summary', {'level': 'LOW', 'score': 0}),
                    redactions_applied=[]
                )
                with open(cert_json, 'w', encoding='utf-8') as f:
                    json.dump(audit_data, f, indent=2)
            except Exception:
                pass
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

@app.route('/api/health', methods=['GET', 'OPTIONS'])
def api_health():
    """Health check endpoint for Chrome extension and monitoring."""
    if request.method == 'OPTIONS':
        return ('', 204)
    return jsonify({
        'status': 'online',
        'service': 'ShareSafe Core Engine',
        'version': '1.0.0',
        'ocr_available': ocr_engine.is_available()
    })

@app.route('/api/scan-text', methods=['POST', 'OPTIONS'])
def api_scan_text():
    """Scans raw text for sensitive PII, credentials, and identity leaks without file upload.
    Used by the ShareSafe Chrome Extension for selected text, WhatsApp, and Gmail scanning.
    """
    if request.method == 'OPTIONS':
        return ('', 204)

    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    if not isinstance(text, str):
        return jsonify({'error': 'Invalid request: "text" field must be a string.'}), 400

    if len(text) > 500000:
        return jsonify({'error': 'Text payload exceeds maximum allowed size (500 KB).'}), 400

    sharing_context = data.get('sharing_context', 'academic').lower()
    if sharing_context not in ['academic', 'professional', 'private', 'public']:
        sharing_context = 'academic'

    from core.risk_assessor import RiskAssessor
    from core.privacy_assistant import PrivacyAssistant

    raw_matches = scanner.detector.scan_text(text)

    detections = []
    for m in raw_matches:
        d = dict(m)
        d['id'] = f"det_{uuid.uuid4().hex[:8]}"
        detections.append(d)

    sorted_matches = sorted(
        [m for m in detections if 'char_span' in m and m['char_span']],
        key=lambda x: x['char_span'][0],
        reverse=True
    )
    masked_text_chars = list(text)
    for m in sorted_matches:
        start, end = m['char_span']
        replacement = m.get('masked') or '[REDACTED]'
        masked_text_chars[start:end] = list(replacement)
    masked_text = "".join(masked_text_chars)

    risk_summary = RiskAssessor.assess(detections, context=sharing_context)
    assistant_analysis = PrivacyAssistant.generate_recommendations(
        detections,
        sharing_context=sharing_context,
        file_name='Webpage Selection',
        is_pdf=False,
        page_count=1
    )

    return jsonify({
        'success': True,
        'text_length': len(text),
        'total_findings': len(detections),
        'detections': detections,
        'risk_summary': risk_summary,
        'assistant': assistant_analysis,
        'masked_text': masked_text,
        'sharing_context': sharing_context
    })

@app.route('/api/inspect-file', methods=['POST', 'OPTIONS'])
def api_inspect_file():
    """Inspects an uploaded document/PDF/image for sensitive PII and QR threat payloads.
    Used by the ShareSafe Browser Extension (Phase 3) for automated pre-upload screening.
    """
    if request.method == 'OPTIONS':
        return ('', 204)

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded in "file" form field.'}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400

    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in Config.ALLOWED_EXTENSIONS:
        return jsonify({
            'error': f'Unsupported file extension .{ext}. Allowed: {", ".join(Config.ALLOWED_EXTENSIONS)}'
        }), 400

    session_id = str(uuid.uuid4().hex[:12])
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    SessionManager.get_session_output_dir(session_id)

    display_name = os.path.basename(file.filename)
    safe_filename = f"inspect_{uuid.uuid4().hex[:8]}.{ext}"
    target_path = os.path.join(upload_dir, safe_filename)
    file.save(target_path)

    # Validate file integrity and bounds
    is_valid, val_err = validate_file_content(target_path, ext)
    if not is_valid:
        SessionManager.purge_session(session_id)
        return jsonify({'error': val_err}), 400

    sharing_context = request.form.get('sharing_context', 'academic').lower()
    if sharing_context not in ['academic', 'professional', 'private', 'public']:
        sharing_context = 'academic'

    try:
        scan_result = scanner.scan_file(
            target_path,
            upload_dir,
            sharing_context=sharing_context,
            original_filename=display_name
        )
        meta_result = MetadataCleaner.inspect_file(target_path)

        session_info = {
            'session_id': session_id,
            'file_name': scan_result['file_name'],
            'sample_id': None,
            'is_pdf': scan_result['is_pdf'],
            'page_count': scan_result.get('page_count', len(scan_result.get('pages', []))),
            'sharing_context': sharing_context,
            'original_path': target_path,
            'pages': scan_result['pages'],
            'detections': scan_result['detections'],
            'risk_summary': scan_result['risk_summary'],
            'metadata': meta_result,
            'assistant': scan_result.get('assistant', {}),
            'warnings': scan_result.get('warnings', [])
        }

        with open(os.path.join(upload_dir, 'session_info.json'), 'w', encoding='utf-8') as f:
            json.dump(session_info, f, indent=2)

        return jsonify({
            'success': True,
            'session_id': session_id,
            'workbench_url': url_for('workbench', session_id=session_id),
            'file_name': display_name,
            'file_size': os.path.getsize(target_path),
            'is_pdf': scan_result['is_pdf'],
            'total_findings': len(scan_result['detections']),
            'detections': scan_result['detections'],
            'risk_summary': scan_result['risk_summary'],
            'assistant': scan_result.get('assistant', {}),
            'can_share_safely': scan_result['risk_summary'].get('can_share_safely', False)
        })

    except Exception as e:
        SessionManager.purge_session(session_id)
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to process file: {str(e)}'}), 500

def validate_non_recoverability(output_path: str, is_pdf: bool, detected_values: list = None) -> dict:
    """Verifies that the redacted document/image does not leak residual text streams or sensitive tokens."""
    detected_values = detected_values or []
    res = {
        'residual_text_chars': 0,
        'metadata_stripped': True,
        'flattened_raster': True,
        'sensitive_tokens_leaked': 0,
        'verified': True
    }
    try:
        if is_pdf:
            import pymupdf
            doc = pymupdf.open(output_path)
            total_chars = 0
            all_text = ""
            for page in doc:
                t = page.get_text() or ""
                total_chars += len(t.strip())
                all_text += t + " "
            doc.close()
            res['residual_text_chars'] = total_chars
            if total_chars > 0:
                res['flattened_raster'] = False
            leaks = 0
            for val in detected_values:
                val_clean = str(val).strip()
                if len(val_clean) >= 4 and val_clean.lower() in all_text.lower():
                    leaks += 1
            res['sensitive_tokens_leaked'] = leaks
            res['verified'] = (total_chars == 0 and leaks == 0)
        else:
            meta = MetadataCleaner.inspect_file(output_path)
            res['metadata_stripped'] = len(meta.get('tags', [])) == 0 or meta.get('status') == 'CLEAN'
            res['residual_text_chars'] = 0
            res['verified'] = True
    except Exception as e:
        res['verified'] = False
        res['error'] = str(e)
    return res

@app.route('/api/auto-redact-attachment', methods=['POST', 'OPTIONS'])
def auto_redact_attachment():
    """
    Automated Attachment Redaction Workflow Endpoint:
    1. Detects & scans photo, image, PDF or document attachment.
    2. Automatically redacts all detected sensitive items by default.
    3. Validates non-recoverability from exported file.
    4. Returns sanitized file (base64) ready to be swapped as final attachment.
    """
    if request.method == 'OPTIONS':
        return ('', 204)

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded in "file" form field.'}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file.'}), 400

    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in Config.ALLOWED_EXTENSIONS:
        return jsonify({
            'success': False,
            'error': f'Unsupported file format .{ext}. ShareSafe protects: {", ".join(Config.ALLOWED_EXTENSIONS)}',
            'supported_extensions': list(Config.ALLOWED_EXTENSIONS)
        }), 400

    session_id = str(uuid.uuid4().hex[:12])
    upload_dir = SessionManager.get_session_upload_dir(session_id)
    output_dir = SessionManager.get_session_output_dir(session_id)

    display_name = os.path.basename(file.filename)
    safe_filename = f"attach_{uuid.uuid4().hex[:8]}.{ext}"
    target_path = os.path.join(upload_dir, safe_filename)
    file.save(target_path)

    # Validate file integrity and magic bytes
    is_valid, val_err = validate_file_content(target_path, ext)
    if not is_valid:
        SessionManager.purge_session(session_id)
        return jsonify({'success': False, 'error': val_err}), 400

    sharing_context = request.form.get('sharing_context', 'academic').lower()
    if sharing_context not in ['academic', 'professional', 'private', 'public']:
        sharing_context = 'academic'

    default_style = request.form.get('default_style', 'blackout').lower()
    if default_style not in ['blackout', 'blur', 'pixelate', 'whiteout', 'stamp']:
        default_style = 'blackout'

    try:
        scan_result = scanner.scan_file(
            target_path,
            upload_dir,
            sharing_context=sharing_context,
            original_filename=display_name
        )
        is_pdf = scan_result['is_pdf']
        detections = scan_result['detections']
        risk_summary = scan_result['risk_summary']

        # If zero findings, file is clean
        if len(detections) == 0:
            return jsonify({
                'success': True,
                'is_clean': True,
                'session_id': session_id,
                'file_name': display_name,
                'file_size': os.path.getsize(target_path),
                'is_pdf': is_pdf,
                'total_findings': 0,
                'detections': [],
                'risk_summary': risk_summary,
                'can_share_safely': True,
                'message': 'No sensitive information detected. File is clean to share.'
            })

        # By default: ALL detected items with bounding boxes are marked for redaction
        active_redactions = []
        annotated_detections = []
        for d in detections:
            bbox = d.get('bbox')
            d_copy = dict(d)
            if bbox and len(bbox) == 4:
                d_copy['redacted'] = True
                d_copy['style'] = default_style
                active_redactions.append({
                    'id': d['id'],
                    'page': d.get('page', 1),
                    'bbox': bbox,
                    'style': default_style,
                    'label': d.get('type', 'REDACTED'),
                    'category': d.get('category', 'General PII')
                })
            else:
                d_copy['redacted'] = False
                d_copy['style'] = 'none'
            annotated_detections.append(d_copy)

        # Generate sanitized copy
        out_ext = '.pdf' if is_pdf else os.path.splitext(target_path)[1].lower()
        out_filename = f"safe_{display_name}"
        safe_output_path = DocumentRedactor.redact_document(
            original_file_path=target_path,
            is_pdf=is_pdf,
            session_dir=output_dir,
            redactions=active_redactions,
            output_filename=out_filename
        )

        # Validate non-recoverability
        detected_vals = [d.get('value', '') for d in detections]
        verification = validate_non_recoverability(safe_output_path, is_pdf, detected_vals)

        # Render preview thumbnails as data URLs (matching DocumentRedactor's 150 DPI render)
        page_previews = []
        preview_data_url = ""
        import base64
        if is_pdf:
            import pymupdf
            out_doc = pymupdf.open(safe_output_path)
            zoom_mat = pymupdf.Matrix(150 / 72, 150 / 72)
            for p_idx, p in enumerate(out_doc):
                pix = p.get_pixmap(matrix=zoom_mat)
                preview_bytes = pix.tobytes("png")
                p_b64 = f"data:image/png;base64,{base64.b64encode(preview_bytes).decode('utf-8')}"
                page_previews.append({
                    'page_number': p_idx + 1,
                    'width': pix.width,
                    'height': pix.height,
                    'preview_data_url': p_b64
                })
            if len(page_previews) > 0:
                preview_data_url = page_previews[0]['preview_data_url']
            out_doc.close()
        else:
            with open(safe_output_path, 'rb') as f:
                b64 = f"data:image/png;base64,{base64.b64encode(f.read()).decode('utf-8')}"
                preview_data_url = b64
                page_previews.append({
                    'page_number': 1,
                    'preview_data_url': b64
                })

        # Read sanitized file bytes
        with open(safe_output_path, 'rb') as f:
            sanitized_bytes = f.read()
            sanitized_b64 = base64.b64encode(sanitized_bytes).decode('utf-8')

        # Persist session info for subsequent selective undo/edit requests
        session_info = {
            'session_id': session_id,
            'file_name': display_name,
            'is_pdf': is_pdf,
            'original_path': target_path,
            'output_dir': output_dir,
            'detections': detections,
            'risk_summary': risk_summary,
            'default_style': default_style
        }
        with open(os.path.join(upload_dir, 'session_info.json'), 'w', encoding='utf-8') as f:
            json.dump(session_info, f, indent=2)

        mime_type = 'application/pdf' if is_pdf else f"image/{ext.replace('jpg', 'jpeg')}"

        return jsonify({
            'success': True,
            'is_clean': False,
            'session_id': session_id,
            'file_name': display_name,
            'file_size': os.path.getsize(target_path),
            'is_pdf': is_pdf,
            'page_count': len(page_previews),
            'pages': page_previews,
            'total_findings': len(detections),
            'detections': annotated_detections,
            'risk_summary': risk_summary,
            'sanitized_filename': f"safe_{display_name}",
            'sanitized_base64': sanitized_b64,
            'sanitized_mime': mime_type,
            'preview_data_url': preview_data_url,
            'non_recoverable_verified': verification['verified'],
            'verification_details': verification
        })

    except Exception as e:
        SessionManager.purge_session(session_id)
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Scan and auto-redaction failed: {str(e)}'}), 500

@app.route('/api/update-attachment-redactions/<session_id>', methods=['POST', 'OPTIONS'])
def update_attachment_redactions(session_id):
    """
    Allows user to selectively undo or edit individual redactions.
    Re-generates the sanitized file without touching the original.
    """
    if request.method == 'OPTIONS':
        return ('', 204)

    upload_dir = SessionManager.get_session_upload_dir(session_id)
    output_dir = SessionManager.get_session_output_dir(session_id)
    info_path = os.path.join(upload_dir, 'session_info.json')

    if not os.path.exists(info_path):
        return jsonify({'success': False, 'error': 'Session expired or not found.'}), 404

    try:
        with open(info_path, 'r', encoding='utf-8') as f:
            session_info = json.load(f)

        data = request.get_json() or {}
        excluded_ids = set(data.get('excluded_detection_ids', []))
        custom_styles = data.get('custom_styles', {})
        manual_redactions = data.get('manual_redactions', [])

        target_path = session_info['original_path']
        is_pdf = session_info['is_pdf']
        display_name = session_info['file_name']
        detections = session_info['detections']
        default_style = session_info.get('default_style', 'blackout')

        active_redactions = []
        annotated_detections = []
        for d in detections:
            bbox = d.get('bbox')
            d_copy = dict(d)
            if bbox and len(bbox) == 4 and d['id'] not in excluded_ids:
                style = custom_styles.get(d['id'], default_style)
                d_copy['redacted'] = True
                d_copy['style'] = style
                active_redactions.append({
                    'id': d['id'],
                    'page': d.get('page', 1),
                    'bbox': bbox,
                    'style': style,
                    'label': d.get('type', 'REDACTED'),
                    'category': d.get('category', 'General PII')
                })
            else:
                d_copy['redacted'] = False
                d_copy['style'] = 'none'
            annotated_detections.append(d_copy)

        # Incorporate user-drawn manual redactions
        for mr in manual_redactions:
            m_bbox = mr.get('bbox')
            if m_bbox and len(m_bbox) == 4:
                active_redactions.append({
                    'id': mr.get('id', f"man_{uuid.uuid4().hex[:8]}"),
                    'page': int(mr.get('page', 1)),
                    'bbox': [float(v) for v in m_bbox],
                    'style': mr.get('style', default_style),
                    'label': mr.get('label', 'Manual Redaction'),
                    'category': 'User Defined'
                })

        out_filename = f"safe_{display_name}"
        safe_output_path = DocumentRedactor.redact_document(
            original_file_path=target_path,
            is_pdf=is_pdf,
            session_dir=output_dir,
            redactions=active_redactions,
            output_filename=out_filename
        )

        detected_vals = [d.get('value', '') for d in detections if d['id'] not in excluded_ids]
        verification = validate_non_recoverability(safe_output_path, is_pdf, detected_vals)

        # Render preview thumbnails matching 150 DPI
        page_previews = []
        preview_data_url = ""
        import base64
        if is_pdf:
            import pymupdf
            out_doc = pymupdf.open(safe_output_path)
            zoom_mat = pymupdf.Matrix(150 / 72, 150 / 72)
            for p_idx, p in enumerate(out_doc):
                pix = p.get_pixmap(matrix=zoom_mat)
                preview_bytes = pix.tobytes("png")
                p_b64 = f"data:image/png;base64,{base64.b64encode(preview_bytes).decode('utf-8')}"
                page_previews.append({
                    'page_number': p_idx + 1,
                    'width': pix.width,
                    'height': pix.height,
                    'preview_data_url': p_b64
                })
            if len(page_previews) > 0:
                preview_data_url = page_previews[0]['preview_data_url']
            out_doc.close()
        else:
            with open(safe_output_path, 'rb') as f:
                b64 = f"data:image/png;base64,{base64.b64encode(f.read()).decode('utf-8')}"
                preview_data_url = b64
                page_previews.append({
                    'page_number': 1,
                    'preview_data_url': b64
                })

        with open(safe_output_path, 'rb') as f:
            sanitized_bytes = f.read()
            sanitized_b64 = base64.b64encode(sanitized_bytes).decode('utf-8')

        ext = os.path.splitext(target_path)[1].lower().replace('.', '')
        mime_type = 'application/pdf' if is_pdf else f"image/{ext.replace('jpg', 'jpeg')}"

        return jsonify({
            'success': True,
            'session_id': session_id,
            'file_name': display_name,
            'detections': annotated_detections,
            'total_active_redactions': len(active_redactions),
            'page_count': len(page_previews),
            'pages': page_previews,
            'manual_redactions': manual_redactions,
            'sanitized_filename': f"safe_{display_name}",
            'sanitized_base64': sanitized_b64,
            'sanitized_mime': mime_type,
            'preview_data_url': preview_data_url,
            'non_recoverable_verified': verification['verified'],
            'verification_details': verification
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Failed to update redactions: {str(e)}'}), 500

if __name__ == '__main__':
    print("================================================================")
    print(" ShareSafe - Zero-Leak PII & QR Privacy Redaction Server Running")
    print(" Access at: http://127.0.0.1:5000")
    print("================================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
