/**
 * ShareSafe - Main Application JavaScript (Uploads, Demos, Modals)
 */

function triggerFilePicker() {
    const input = document.getElementById('fileInput');
    if (input) {
        input.click();
    } else {
        window.location.href = '/#uploadSection';
    }
}

document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        triggerFilePicker();
    }
});

// Drag & Drop Handlers
function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById('uploadForm');
    if (zone) zone.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById('uploadForm');
    if (zone) zone.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    const zone = document.getElementById('uploadForm');
    if (zone) zone.classList.remove('drag-over');

    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
        uploadFileObject(dt.files[0]);
    }
}

function setSharingContext(ctx) {
    const input = document.getElementById('sharingContextInput');
    if (input) input.value = ctx;

    const chips = document.querySelectorAll('.context-chip');
    chips.forEach(chip => {
        if (chip.getAttribute('data-context') === ctx) {
            chip.classList.add('active');
        } else {
            chip.classList.remove('active');
        }
    });

    const desc = document.getElementById('contextDescText');
    if (desc) {
        switch (ctx) {
            case 'academic':
                desc.innerText = 'Tuned for student assignments & research papers';
                break;
            case 'professional':
                desc.innerText = 'Strict enterprise guardrails for emails, keys, and tokens';
                break;
            case 'private':
                desc.innerText = 'Direct peer sharing: personal identifiers shielded';
                break;
            case 'public':
                desc.innerText = 'Maximum defensive redaction for public social sharing';
                break;
        }
    }
}

function handleFileSelect(e) {
    if (e.target.files && e.target.files.length > 0) {
        uploadFileObject(e.target.files[0]);
    }
}

function uploadFileObject(file) {
    const idleBox = document.getElementById('dropzoneIdle');
    const scanBox = document.getElementById('dropzoneScanning');

    if (idleBox) idleBox.style.display = 'none';
    if (scanBox) scanBox.style.display = 'block';

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
    .then(res => res.json())
    .then(data => {
        if (data.success && data.redirect_url) {
            window.location.href = data.redirect_url;
        } else {
            alert('Upload error: ' + (data.error || 'Failed to analyze file.'));
            if (idleBox) idleBox.style.display = 'block';
            if (scanBox) scanBox.style.display = 'none';
        }
    })
    .catch(err => {
        alert('Upload network error: ' + err.message);
        if (idleBox) idleBox.style.display = 'block';
        if (scanBox) scanBox.style.display = 'none';
    });
}

function loadSample(sampleId) {
    const idleBox = document.getElementById('dropzoneIdle');
    const scanBox = document.getElementById('dropzoneScanning');

    if (idleBox) idleBox.style.display = 'none';
    if (scanBox) {
        scanBox.style.display = 'block';
        const title = document.getElementById('scanStatusTitle');
        if (title) title.innerText = 'Loading & Scanning Fictional Sample...';
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
    .then(res => res.json())
    .then(data => {
        if (data.success && data.redirect_url) {
            window.location.href = data.redirect_url;
        } else {
            alert('Error loading sample: ' + (data.error || 'Unknown error'));
            if (idleBox) idleBox.style.display = 'block';
            if (scanBox) scanBox.style.display = 'none';
        }
    })
    .catch(err => {
        alert('Network error loading sample: ' + err.message);
        if (idleBox) idleBox.style.display = 'block';
        if (scanBox) scanBox.style.display = 'none';
    });
}

// OCR Engine Modal Logic
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
            badge.className = 'badge-tag';
            badge.style.background = 'rgba(16, 185, 129, 0.2)';
            badge.style.color = '#10b981';
            badge.innerText = `Active (v${status.version || 'OK'})`;
            desc.innerText = status.message || 'Tesseract engine is operational.';
        } else {
            badge.className = 'badge-tag';
            badge.style.background = 'rgba(245, 158, 11, 0.2)';
            badge.style.color = '#f59e0b';
            badge.innerText = 'Binary Not In Path';
            desc.innerText = status.message;
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
            alertBox.className = 'flash-alert';
            alertBox.style.background = 'rgba(16, 185, 129, 0.15)';
            alertBox.style.borderColor = '#10b981';
            alertBox.style.color = '#a7f3d0';
            alertBox.innerText = res.message;
            setTimeout(() => { openOcrModal(); }, 1000);
        } else {
            alertBox.className = 'flash-alert';
            alertBox.style.background = 'rgba(239, 68, 68, 0.15)';
            alertBox.style.borderColor = '#ef4444';
            alertBox.style.color = '#fecaca';
            alertBox.innerText = res.message;
        }
    });
}

// QR Threat Inspector Modal Logic
let currentInspectingQrId = null;

function openQrThreatInspector(detId) {
    currentInspectingQrId = detId;
    const modal = document.getElementById('qrModal');
    if (!modal) return;

    // Retrieve detection info from session data
    let detection = null;
    if (window.workbenchSession && window.workbenchSession.detections) {
        detection = window.workbenchSession.detections.find(d => d.id === detId);
    }

    if (!detection) return;

    const banner = document.getElementById('qrThreatBanner');
    const title = document.getElementById('qrThreatTitle');
    const desc = document.getElementById('qrThreatDesc');
    const raw = document.getElementById('qrRawPayload');
    const tbody = document.querySelector('#qrFieldsTable tbody');

    title.innerText = detection.label || 'QR Code Detected';
    desc.innerText = detection.details || 'Scannable payload detected.';
    raw.innerText = detection.value || '[No decoded string]';

    // Clear and populate fields
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
