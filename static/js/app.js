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

function executeUploadWithFile(file) {
    const idleBox = document.getElementById('dropzoneIdle');
    const selectedBox = document.getElementById('dropzoneSelected');
    const scanBox = document.getElementById('dropzoneScanning');
    const errorBox = document.getElementById('dropzoneError');

    if (idleBox) idleBox.style.display = 'none';
    if (selectedBox) selectedBox.style.display = 'none';
    if (errorBox) errorBox.style.display = 'none';
    if (scanBox) scanBox.style.display = 'flex';

    // Status progression messaging
    const title = document.getElementById('scanStatusTitle');
    const sub = document.getElementById('scanStatusSubtitle');
    if (title) title.innerText = 'Performing Deep Privacy Scan...';
    if (sub) sub.innerText = 'Decompiling vector streams, applying OCR, and checking Verhoeff/Luhn checksums...';

    const formData = new FormData();
    formData.append('file', file);
    const ctxInput = document.getElementById('sharingContextInput');
    if (ctxInput && ctxInput.value) {
        formData.append('sharing_context', ctxInput.value);
    }

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(async res => {
        let data = null;
        try {
            data = await res.json();
        } catch (e) {
            data = null;
        }
        if (!res.ok) {
            const errorMsg = (data && data.error) ? data.error : `Server communication error (${res.status} ${res.statusText})`;
            showUploadError('Analysis Failed', errorMsg);
            return;
        }
        if (data && data.success && data.redirect_url) {
            if (sub) sub.innerText = 'Verification complete. Transferring to Privacy Studio...';
            window.location.href = data.redirect_url;
        } else {
            showUploadError('Analysis Failed', (data && data.error) || 'Failed to inspect document.');
        }
    })
    .catch(err => {
        showUploadError('Network Communication Error', err.message);
    });
}

// Sharing Context Selector
function setSharingContext(ctx) {
    const input = document.getElementById('sharingContextInput');
    if (input) input.value = ctx;

    const buttons = document.querySelectorAll('.segment-btn[data-context], .profile-chip[data-context]');
    buttons.forEach(btn => {
        const isTarget = btn.getAttribute('data-context') === ctx;
        if (isTarget) {
            btn.classList.add('active');
            btn.setAttribute('aria-selected', 'true');
        } else {
            btn.classList.remove('active');
            btn.setAttribute('aria-selected', 'false');
        }
    });

    const desc = document.getElementById('contextDescText');
    if (desc) {
        switch (ctx) {
            case 'academic':
                desc.innerText = 'Tuned for student assignments, coursework, and research papers with standard PII shielding.';
                break;
            case 'professional':
                desc.innerText = 'Strict enterprise guardrails for API keys, secret tokens, credentials, and financial invoices.';
                break;
            case 'private':
                desc.innerText = 'Direct peer sharing: personal phone numbers, addresses, and identity numbers shielded.';
                break;
            case 'public':
                desc.innerText = 'Maximum defensive redaction for broad social sharing, public slide decks, and external forums.';
                break;
        }
    }
}

// Demo Vault Sample Loader
function loadSample(sampleId) {
    const idleBox = document.getElementById('dropzoneIdle');
    const selectedBox = document.getElementById('dropzoneSelected');
    const scanBox = document.getElementById('dropzoneScanning');
    const errorBox = document.getElementById('dropzoneError');

    if (idleBox) idleBox.style.display = 'none';
    if (selectedBox) selectedBox.style.display = 'none';
    if (errorBox) errorBox.style.display = 'none';
    if (scanBox) {
        scanBox.style.display = 'flex';
        const title = document.getElementById('scanStatusTitle');
        const sub = document.getElementById('scanStatusSubtitle');
        if (title) title.innerText = 'Loading Synthetic Demonstration Sample...';
        if (sub) sub.innerText = 'Simulating forensic extraction on verified synthetic dataset...';
    }

    const formData = new FormData();
    formData.append('sample_id', sampleId);
    const ctxInput = document.getElementById('sharingContextInput');
    if (ctxInput && ctxInput.value) {
        formData.append('sharing_context', ctxInput.value);
    }

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(async res => {
        let data = null;
        try {
            data = await res.json();
        } catch (e) {
            data = null;
        }
        if (!res.ok) {
            const errorMsg = (data && data.error) ? data.error : `Server communication error (${res.status} ${res.statusText})`;
            showUploadError('Error Loading Sample', errorMsg);
            return;
        }
        if (data && data.success && data.redirect_url) {
            window.location.href = data.redirect_url;
        } else {
            showUploadError('Error Loading Sample', (data && data.error) || 'Failed to load demo document.');
        }
    })
    .catch(err => {
        showUploadError('Network Error', err.message);
    });
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


