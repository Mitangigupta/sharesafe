/**
 * ShareSafe - Sovereign Privacy & Document Redaction Studio
 * Client Controller: Multi-State Upload Pipeline, Context Selector, Engine Config & QR Inspector
 */

const MAX_FILE_SIZE = 30 * 1024 * 1024; // 30 MB
const ALLOWED_EXTS = ['pdf', 'png', 'jpg', 'jpeg', 'webp', 'bmp'];

let currentStagedFile = null;
let currentInspectingQrId = null;

function triggerFilePicker() {
    const input = document.getElementById('fileInput');
    if (input) {
        input.click();
    } else {
        window.location.href = '/#uploadSection';
    }
}

// Drag & Drop Handlers
function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById('uploadForm');
    if (zone) zone.classList.add('drag-active');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById('uploadForm');
    if (zone) zone.classList.remove('drag-active');
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById('uploadForm');
    if (zone) zone.classList.remove('drag-active');

    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
        stageSelectedFile(dt.files[0]);
    }
}

// File Selection Staging & Client Validation
function handleFileSelect(e) {
    if (e.target.files && e.target.files.length > 0) {
        stageSelectedFile(e.target.files[0]);
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function stageSelectedFile(file) {
    if (!file) return;

    const ext = file.name.split('.').pop().toLowerCase();

    // 1. Validate Extension
    if (!ALLOWED_EXTS.includes(ext)) {
        showUploadError(
            'Unsupported File Format',
            `File extension .${ext} is not supported. Please select a PDF, PNG, JPG, WEBP, or BMP document.`
        );
        return;
    }

    // 2. Validate File Size
    if (file.size > MAX_FILE_SIZE) {
        showUploadError(
            'File Exceeds Size Limit',
            `File size (${formatBytes(file.size)}) exceeds the maximum allowed limit of 30 MB.`
        );
        return;
    }

    currentStagedFile = file;

    const idleBox = document.getElementById('dropzoneIdle');
    const selectedBox = document.getElementById('dropzoneSelected');
    const errorBox = document.getElementById('dropzoneError');
    const scanBox = document.getElementById('dropzoneScanning');

    if (idleBox) idleBox.style.display = 'none';
    if (errorBox) errorBox.style.display = 'none';
    if (scanBox) scanBox.style.display = 'none';
    if (selectedBox) selectedBox.style.display = 'flex';

    // Populate metadata
    const nameEl = document.getElementById('selectedFileName');
    const sizeEl = document.getElementById('selectedFileSize');
    const typeEl = document.getElementById('selectedFileType');
    const iconEl = document.getElementById('selectedFileIcon');

    if (nameEl) nameEl.innerText = file.name;
    if (sizeEl) sizeEl.innerText = formatBytes(file.size);
    if (typeEl) typeEl.innerText = ext === 'pdf' ? 'PDF Document' : 'Raster Image (' + ext.toUpperCase() + ')';
    if (iconEl) {
        iconEl.className = ext === 'pdf' ? 'fa-solid fa-file-pdf text-coral' : 'fa-solid fa-file-image text-coral';
    }
}

function clearSelectedFile() {
    currentStagedFile = null;
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.value = '';
    resetUploadDropzone();
}

function resetUploadDropzone() {
    currentStagedFile = null;
    const idleBox = document.getElementById('dropzoneIdle');
    const selectedBox = document.getElementById('dropzoneSelected');
    const errorBox = document.getElementById('dropzoneError');
    const scanBox = document.getElementById('dropzoneScanning');

    if (idleBox) idleBox.style.display = 'block';
    if (selectedBox) selectedBox.style.display = 'none';
    if (errorBox) errorBox.style.display = 'none';
    if (scanBox) scanBox.style.display = 'none';
}

function showUploadError(title, message) {
    const idleBox = document.getElementById('dropzoneIdle');
    const selectedBox = document.getElementById('dropzoneSelected');
    const errorBox = document.getElementById('dropzoneError');
    const scanBox = document.getElementById('dropzoneScanning');

    if (idleBox) idleBox.style.display = 'none';
    if (selectedBox) selectedBox.style.display = 'none';
    if (scanBox) scanBox.style.display = 'none';
    if (errorBox) {
        errorBox.style.display = 'flex';
        const titleEl = document.getElementById('uploadErrorTitle');
        const msgEl = document.getElementById('uploadErrorMessage');
        if (titleEl) titleEl.innerText = title;
        if (msgEl) msgEl.innerText = message;
    }
}

function submitSelectedFile() {
    if (!currentStagedFile) return;
    executeUploadWithFile(currentStagedFile);
}

function _startScanProgressSSE(sessionId) {
    var steps = {
        validate: { label: "Validating document structure...",    pct: 10 },
        pages:    { label: "Extracting page content...",          pct: 25 },
        ocr:      { label: "Running OCR text recognition...",     pct: 45 },
        risk:     { label: "Assessing risk & compliance...",      pct: 75 },
        ai:       { label: "Generating AI recommendations...",    pct: 90 },
        done:     { label: "Scan complete. Opening workspace...", pct: 100 },
        heartbeat:{ label: "Deep scanning in progress...",        pct: 55 }
    };
    var title = document.getElementById("scanStatusTitle");
    var sub   = document.getElementById("scanStatusSubtitle");
    var bar   = document.querySelector(".scanner-progress-bar");
    if (bar)   bar.classList.add("sse-active");

    var es = new EventSource("/api/scan-progress/" + sessionId);
    es.onmessage = function(e) {
        try {
            var ev = JSON.parse(e.data);
            var info = steps[ev.step] || { label: ev.label || "Processing...", pct: ev.pct || 50 };
            if (sub)   sub.innerText   = info.label;
            if (bar)   bar.style.width = info.pct + "%";
            if (title) title.innerText = ev.pct >= 100 ? "Scan Complete \u2014 Transferring..." : "Deep Privacy Scan Running...";
        } catch(err) {}
    };
    es.onerror = function() { es.close(); };
    return es;
}

function executeUploadWithFile(file) {
    var idleBox     = document.getElementById("dropzoneIdle");
    var selectedBox = document.getElementById("dropzoneSelected");
    var scanBox     = document.getElementById("dropzoneScanning");
    var errorBox    = document.getElementById("dropzoneError");

    if (idleBox)     idleBox.style.display     = "none";
    if (selectedBox) selectedBox.style.display = "none";
    if (errorBox)    errorBox.style.display    = "none";
    if (scanBox)     scanBox.style.display     = "flex";

    var title = document.getElementById("scanStatusTitle");
    var sub   = document.getElementById("scanStatusSubtitle");
    var bar   = document.querySelector(".scanner-progress-bar");
    if (title) title.innerText = "Uploading document...";
    if (sub)   sub.innerText   = "Preparing for deep privacy scan...";
    if (bar)   { bar.style.transition = "width 0.5s ease"; bar.style.width = "5%"; }

    var formData = new FormData();
    formData.append("file", file);
    var ctxInput = document.getElementById("sharingContextInput");
    if (ctxInput && ctxInput.value) formData.append("sharing_context", ctxInput.value);

    // Start SSE listener before the POST so we catch all events
    var tempId = "pending";
    var esHolder = { es: null };

    fetch("/upload", { method: "POST", body: formData })
    .then(function(res) { return res.json().then(function(d) { return { ok: res.ok, data: d }; }); })
    .then(function(r) {
        if (!r.ok || !r.data || !r.data.success) {
            showUploadError("Analysis Failed", (r.data && r.data.error) || "Failed to process document.");
            return;
        }
        // Wire SSE now we have the real session_id
        if (esHolder.es) esHolder.es.close();
        esHolder.es = _startScanProgressSSE(r.data.session_id);
        // Also redirect on done
        var redirectUrl = r.data.redirect_url;
        var origOnMsg = esHolder.es.onmessage;
        esHolder.es.onmessage = function(e) {
            origOnMsg && origOnMsg(e);
            try {
                var ev = JSON.parse(e.data);
                if (ev.pct >= 100) {
                    esHolder.es.close();
                    setTimeout(function() { window.location.href = redirectUrl; }, 400);
                }
            } catch(err) {}
        };
    })
    .catch(function(err) { showUploadError("Network Error", err.message); });
}

// Demo Vault Sample Loader
function loadSample(sampleId) {
    var idleBox     = document.getElementById("dropzoneIdle");
    var selectedBox = document.getElementById("dropzoneSelected");
    var scanBox     = document.getElementById("dropzoneScanning");
    var errorBox    = document.getElementById("dropzoneError");

    if (idleBox)     idleBox.style.display     = "none";
    if (selectedBox) selectedBox.style.display = "none";
    if (errorBox)    errorBox.style.display    = "none";
    if (scanBox)     scanBox.style.display     = "flex";

    var title = document.getElementById("scanStatusTitle");
    var sub   = document.getElementById("scanStatusSubtitle");
    var bar   = document.querySelector(".scanner-progress-bar");
    if (title) title.innerText = "Loading Synthetic Demo Sample...";
    if (sub)   sub.innerText   = "Preparing forensic extraction pipeline...";
    if (bar)   { bar.style.transition = "width 0.5s ease"; bar.style.width = "5%"; }

    var formData = new FormData();
    formData.append("sample_id", sampleId);
    var ctxInput = document.getElementById("sharingContextInput");
    if (ctxInput && ctxInput.value) formData.append("sharing_context", ctxInput.value);

    var esHolder = { es: null };

    fetch("/upload", { method: "POST", body: formData })
    .then(function(res) { return res.json().then(function(d) { return { ok: res.ok, data: d }; }); })
    .then(function(r) {
        if (!r.ok || !r.data || !r.data.success) {
            showUploadError("Error Loading Sample", (r.data && r.data.error) || "Failed to load demo.");
            return;
        }
        if (esHolder.es) esHolder.es.close();
        esHolder.es = _startScanProgressSSE(r.data.session_id);
        var redirectUrl = r.data.redirect_url;
        var origOnMsg = esHolder.es.onmessage;
        esHolder.es.onmessage = function(e) {
            origOnMsg && origOnMsg(e);
            try {
                var ev = JSON.parse(e.data);
                if (ev.pct >= 100) {
                    esHolder.es.close();
                    setTimeout(function() { window.location.href = redirectUrl; }, 400);
                }
            } catch(err) {}
        };
    })
    .catch(function(err) { showUploadError("Network Error", err.message); });
}

// Engine Settings Modal Logic
function openOcrModal() {
    const modal = document.getElementById('ocrModal');
    if (!modal) return;
    modal.style.display = 'flex';

    fetch('/api/ocr-status')
    .then(r => r.json())
    .then(status => {
        const badge = document.getElementById('ocrStatusBadge');
        const desc = document.getElementById('ocrStatusMessage');
        const input = document.getElementById('tesseractCustomPath');

        if (status.available) {
            badge.className = 'engine-chip engine-active';
            badge.innerText = `Active (v${status.version || 'OK'})`;
            desc.innerText = status.message || 'Tesseract OCR engine is operational for rasterized images.';
        } else {
            badge.className = 'engine-chip engine-standard';
            badge.innerText = 'Standard Fallback Active';
            desc.innerText = status.message || 'PyMuPDF native extraction active for digital PDFs. OCR binary optional.';
        }

        if (status.path && input) {
            input.value = status.path;
        }
    });
}

function closeOcrModal() {
    const modal = document.getElementById('ocrModal');
    if (modal) modal.style.display = 'none';
}

function saveOcrPath() {
    const input = document.getElementById('tesseractCustomPath');
    const alertBox = document.getElementById('ocrUpdateAlert');
    if (!input) return;

    const path = input.value.trim();
    fetch('/api/settings/ocr-path', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: path })
    })
    .then(r => r.json())
    .then(res => {
        alertBox.style.display = 'block';
        if (res.success) {
            alertBox.className = 'modal-inline-alert alert-success';
            alertBox.innerText = res.message;
            setTimeout(() => { openOcrModal(); }, 1200);
        } else {
            alertBox.className = 'modal-inline-alert alert-error';
            alertBox.innerText = res.message;
        }
    });
}

// QR Threat Inspector Modal Logic
function openQrThreatInspector(detId) {
    currentInspectingQrId = detId;
    const modal = document.getElementById('qrModal');
    if (!modal) return;

    let detection = null;
    if (window.workbenchSession && window.workbenchSession.detections) {
        detection = window.workbenchSession.detections.find(d => d.id === detId);
    }

    if (!detection) return;

    const title = document.getElementById('qrThreatTitle');
    const desc = document.getElementById('qrThreatDesc');
    const raw = document.getElementById('qrRawPayload');
    const tbody = document.querySelector('#qrFieldsTable tbody');

    title.innerText = detection.label || 'QR Payload Detected';
    desc.innerText = detection.details || 'Scannable routing payload discovered.';
    raw.innerText = detection.value || '[No decoded string]';

    if (tbody) {
        tbody.innerHTML = '';
        const fields = detection.extracted_fields || {};
        const entries = Object.entries(fields);
        if (entries.length > 0) {
            entries.forEach(([k, v]) => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td><strong>${escapeHtml(k)}</strong></td><td><code>${escapeHtml(String(v))}</code></td>`;
                tbody.appendChild(tr);
            });
            document.getElementById('qrFieldsWrapper').style.display = 'block';
        } else {
            document.getElementById('qrFieldsWrapper').style.display = 'none';
        }
    }

    modal.style.display = 'flex';
}

function closeQrModal() {
    const modal = document.getElementById('qrModal');
    if (modal) modal.style.display = 'none';
}

function redactThisQr() {
    if (currentInspectingQrId && typeof window.setDetectionSelected === 'function') {
        window.setDetectionSelected(currentInspectingQrId, true);
    }
    closeQrModal();
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, function(m) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[m];
    });
}

// Global Keyboard Shortcut & Nav Search Handler
document.addEventListener('DOMContentLoaded', () => {
    document.addEventListener('keydown', (e) => {
        if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
            e.preventDefault();
            const searchField = document.getElementById('findingsSearchInput');
            if (searchField) {
                searchField.focus();
                searchField.select();
            } else {
                triggerFilePicker();
            }
        } else if (e.key === 'Escape') {
            closeOcrModal();
            closeQrModal();
        }
    });
});



// Mobile Navigation Drawer Toggle
function toggleMobileNav() {
    const menu = document.getElementById('navLinksMenu');
    const toggle = document.getElementById('navMobileToggle');
    if (!menu) return;
    const isOpen = menu.classList.toggle('mobile-open');
    if (toggle) {
        toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        toggle.innerHTML = isOpen ? '<i class="fa-solid fa-xmark"></i>' : '<i class="fa-solid fa-bars"></i>';
    }
}
