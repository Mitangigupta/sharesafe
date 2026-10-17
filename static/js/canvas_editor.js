/**
 * ShareSafe - Interactive Workbench Canvas Editor
 * Manages Bounding Boxes, Manual Redactions, Before/After Split Comparison & Safe Export
 */

let sessionData = null;
let currentPage = 1;
let currentZoom = 1.0;
let globalStyle = 'blackout';
let selectedIds = new Set();
let manualRedactions = []; // [{ id, page, bbox: [x,y,w,h], style, label }]
let isDrawMode = false;
let isDrawing = false;
let drawStartX = 0, drawStartY = 0;
let redactedPreviews = [];

document.addEventListener('DOMContentLoaded', () => {
    const rawData = document.getElementById('sessionJsonData');
    if (!rawData) return;

    try {
        sessionData = JSON.parse(rawData.textContent);
        window.workbenchSession = sessionData;
    } catch (e) {
        console.error("Failed to parse session json:", e);
        return;
    }

    // Default: auto-select all Critical and High risk detections
    sessionData.detections.forEach(d => {
        if (d.risk === 'CRITICAL' || d.risk === 'HIGH') {
            selectedIds.add(d.id);
        }
    });

    const img = document.getElementById('pagePreviewImg');
    if (img) {
        if (img.complete && img.naturalWidth !== 0) {
            initCanvasDimensions();
        } else {
            img.addEventListener('load', initCanvasDimensions);
        }
    } else {
        initCanvasDimensions();
    }
    initSplitSliderEvents();
});

function initCanvasDimensions() {
    const img = document.getElementById('pagePreviewImg');
    if (!img) return;

    if (!img.naturalWidth || img.clientWidth === 0) {
        setTimeout(initCanvasDimensions, 60);
        return;
    }

    renderBoundingBoxes();
    setupDrawingCanvas();
}

window.addEventListener('resize', () => {
    renderBoundingBoxes();
    setupDrawingCanvas();
    syncAfterImageDimensions();
});

// Calculate current scale between natural image pixels and displayed DOM pixels
function getScaleFactors() {
    const img = document.getElementById('pagePreviewImg');
    if (!img || !img.naturalWidth || !img.clientWidth) {
        return { scaleX: 1, scaleY: 1, naturalW: 1000, naturalH: 1000 };
    }
    return {
        scaleX: img.clientWidth / img.naturalWidth,
        scaleY: img.clientHeight / img.naturalHeight,
        naturalW: img.naturalWidth,
        naturalH: img.naturalHeight
    };
}

// Render bounding boxes over the image
function renderBoundingBoxes() {
    const overlay = document.getElementById('boxOverlayLayer');
    if (!overlay || !sessionData) return;
    overlay.innerHTML = '';

    const { scaleX, scaleY } = getScaleFactors();

    // 1. Render automated detections for this page
    const pageDets = sessionData.detections.filter(d => (d.page || 1) === currentPage);

    pageDets.forEach(d => {
        if (!d.bbox || d.bbox.length !== 4) return;
        const [x, y, w, h] = d.bbox;

        const box = document.createElement('div');
        box.id = `box-${d.id}`;
        box.className = `box-overlay box-${d.risk.toLowerCase()}`;
        if (!selectedIds.has(d.id)) {
            box.classList.add('deselected');
        }

        box.style.left = `${x * scaleX}px`;
        box.style.top = `${y * scaleY}px`;
        box.style.width = `${w * scaleX}px`;
        box.style.height = `${h * scaleY}px`;
        box.title = `${d.label}: ${d.masked} (${d.risk} Risk)`;

        box.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleDetection(d.id);
        });

        box.addEventListener('mouseenter', () => highlightItemInList(d.id));
        box.addEventListener('mouseleave', () => unhighlightItemInList(d.id));

        overlay.appendChild(box);
    });

    // 2. Render manual user-drawn boxes for this page
    const pageManuals = manualRedactions.filter(m => m.page === currentPage);
    pageManuals.forEach(m => {
        const [x, y, w, h] = m.bbox;
        const box = document.createElement('div');
        box.id = `box-${m.id}`;
        box.className = 'box-overlay box-manual';
        box.style.left = `${x * scaleX}px`;
        box.style.top = `${y * scaleY}px`;
        box.style.width = `${w * scaleX}px`;
        box.style.height = `${h * scaleY}px`;
        box.title = `Manual Redaction: ${m.label}`;
        overlay.appendChild(box);
    });
}

// Setup drawing canvas for manual redactions
function setupDrawingCanvas() {
    const canvas = document.getElementById('drawingCanvas');
    const img = document.getElementById('pagePreviewImg');
    if (!canvas || !img || !img.clientWidth || !img.clientHeight) return;

    canvas.width = img.clientWidth;
    canvas.height = img.clientHeight;

    const ctx = canvas.getContext('2d');

    canvas.onmousedown = (e) => {
        if (!isDrawMode) return;
        const rect = canvas.getBoundingClientRect();
        drawStartX = (e.clientX - rect.left) / currentZoom;
        drawStartY = (e.clientY - rect.top) / currentZoom;
        isDrawing = true;
    };

    canvas.onmousemove = (e) => {
        if (!isDrawing || !isDrawMode) return;
        const rect = canvas.getBoundingClientRect();
        const currentX = (e.clientX - rect.left) / currentZoom;
        const currentY = (e.clientY - rect.top) / currentZoom;

        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.strokeStyle = '#ec4899';
        ctx.lineWidth = 2;
        ctx.fillStyle = 'rgba(236, 72, 153, 0.25)';

        const w = currentX - drawStartX;
        const h = currentY - drawStartY;
        ctx.fillRect(drawStartX, drawStartY, w, h);
        ctx.strokeRect(drawStartX, drawStartY, w, h);
    };

    canvas.onmouseup = (e) => {
        if (!isDrawing || !isDrawMode) return;
        isDrawing = false;
        const rect = canvas.getBoundingClientRect();
        const endX = (e.clientX - rect.left) / currentZoom;
        const endY = (e.clientY - rect.top) / currentZoom;
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const xMin = Math.min(drawStartX, endX);
        const yMin = Math.min(drawStartY, endY);
        const boxW = Math.abs(endX - drawStartX);
        const boxH = Math.abs(endY - drawStartY);

        // Discard accidental clicks smaller than 8px
        if (boxW < 8 || boxH < 8) return;

        const { scaleX, scaleY } = getScaleFactors();
        // Convert to document native coordinates
        const nativeX = Math.round(xMin / scaleX);
        const nativeY = Math.round(yMin / scaleY);
        const nativeW = Math.round(boxW / scaleX);
        const nativeH = Math.round(boxH / scaleY);

        const manualId = `manual_${Date.now()}`;
        const newManual = {
            id: manualId,
            page: currentPage,
            bbox: [nativeX, nativeY, nativeW, nativeH],
            style: globalStyle,
            label: `Custom Region #${manualRedactions.length + 1}`
        };

        manualRedactions.push(newManual);
        if (typeof switchSidebarTab === 'function') switchSidebarTab('manual');
        updateManualRedactionsUI();
        renderBoundingBoxes();
    };
}

function toggleDrawMode() {
    isDrawMode = !isDrawMode;
    const btn = document.getElementById('drawModeBtn');
    const text = document.getElementById('drawModeText');
    const canvas = document.getElementById('drawingCanvas');

    if (isDrawMode) {
        btn.classList.add('active');
        text.innerText = 'Exit Drawing';
        canvas.classList.add('active-draw');
        if (typeof switchSidebarTab === 'function') switchSidebarTab('manual');
    } else {
        btn.classList.remove('active');
        text.innerText = 'Draw Manual Box';
        canvas.classList.remove('active-draw');
    }
}

function updateManualRedactionsUI() {
    const list = document.getElementById('manualList');
    const count = document.getElementById('manualCount');
    if (!list || !count) return;

    const badge = document.getElementById('manualCountBadge');
    if (badge) badge.innerText = manualRedactions.length;

    if (manualRedactions.length === 0) {
        list.innerHTML = `<div class="manual-empty-text"><i class="fa-solid fa-draw-polygon"></i><p>No manual boxes added yet. Activate drawing mode to redact custom regions.</p></div>`;
        return;
    }

    list.innerHTML = '';
    manualRedactions.forEach((m, idx) => {
        const item = document.createElement('div');
        item.className = 'manual-item';
        item.innerHTML = `
            <div>
                <strong>${escapeHtml(m.label)}</strong>
                <div style="font-size: 0.7rem; color: var(--text-muted);">Page ${m.page} | ${m.bbox[2]}x${m.bbox[3]}px</div>
            </div>
            <button type="button" class="btn-delete-manual" onclick="deleteManualRedaction('${m.id}')" title="Delete this manual box">
                <i class="fa-solid fa-xmark"></i>
            </button>
        `;
        list.appendChild(item);
    });
}

function deleteManualRedaction(manualId) {
    manualRedactions = manualRedactions.filter(m => m.id !== manualId);
    updateManualRedactionsUI();
    renderBoundingBoxes();
}

// Detection toggles and selections
function toggleDetection(id) {
    if (selectedIds.has(id)) {
        selectedIds.delete(id);
    } else {
        selectedIds.add(id);
    }
    syncCheckbox(id);
    renderBoundingBoxes();
}

window.setDetectionSelected = function(id, isSelected) {
    if (isSelected) selectedIds.add(id);
    else selectedIds.delete(id);
    syncCheckbox(id);
    renderBoundingBoxes();
};

function onCheckboxChange(id) {
    const chk = document.getElementById(`chk-${id}`);
    if (chk) {
        if (chk.checked) selectedIds.add(id);
        else selectedIds.delete(id);
    }
    renderBoundingBoxes();
}

function syncCheckbox(id) {
    const chk = document.getElementById(`chk-${id}`);
    if (chk) {
        chk.checked = selectedIds.has(id);
    }
}

function selectAllDetections() {
    if (!sessionData) return;
    sessionData.detections.forEach(d => selectedIds.add(d.id));
    document.querySelectorAll('.det-checkbox').forEach(c => c.checked = true);
    renderBoundingBoxes();
}

function selectCriticalAndHigh() {
    if (!sessionData) return;
    selectedIds.clear();
    sessionData.detections.forEach(d => {
        if (d.risk === 'CRITICAL' || d.risk === 'HIGH') {
            selectedIds.add(d.id);
        }
    });
    document.querySelectorAll('.det-checkbox').forEach(c => {
        const id = c.getAttribute('data-id');
        c.checked = selectedIds.has(id);
    });
    renderBoundingBoxes();
}

function deselectAllDetections() {
    selectedIds.clear();
    document.querySelectorAll('.det-checkbox').forEach(c => c.checked = false);
    renderBoundingBoxes();
}

function updateGlobalStyle(newStyle) {
    globalStyle = newStyle;
}

function highlightBox(id) {
    const box = document.getElementById(`box-${id}`);
    if (box) box.classList.add('highlighted');
}

function unhighlightBox(id) {
    const box = document.getElementById(`box-${id}`);
    if (box) box.classList.remove('highlighted');
}

function highlightItemInList(id) {
    const item = document.getElementById(`item-${id}`);
    if (item) item.classList.add('highlighted');
}

function unhighlightItemInList(id) {
    const item = document.getElementById(`item-${id}`);
    if (item) item.classList.remove('highlighted');
}

// Zoom & Pan controls
function zoomCanvas(delta) {
    currentZoom = Math.max(0.5, Math.min(2.5, currentZoom + delta));
    applyZoom();
}

function resetCanvasZoom() {
    currentZoom = 1.0;
    applyZoom();
}

function applyZoom() {
    const wrap = document.getElementById('overlayViewport');
    const splitWrap = document.getElementById('splitViewport');
    const redWrap = document.getElementById('redactedViewport');
    const ind = document.getElementById('zoomLevelIndicator');

    if (ind) ind.innerText = `${Math.round(currentZoom * 100)}%`;

    [wrap, splitWrap, redWrap].forEach(el => {
        if (el) el.style.transform = `scale(${currentZoom})`;
    });
}

// Multi-page navigation
function changePage(delta) {
    if (!sessionData || sessionData.page_count <= 1) return;
    const newPage = currentPage + delta;
    if (newPage < 1 || newPage > sessionData.page_count) return;

    currentPage = newPage;
    const pageInd = document.getElementById('currentPageNum');
    if (pageInd) pageInd.innerText = currentPage;

    const pageObj = sessionData.pages[currentPage - 1];
    const previewImg = document.getElementById('pagePreviewImg');
    const beforeImg = document.getElementById('beforeSliderImg');
    const afterImg = document.getElementById('afterSliderImg');
    const soloImg = document.getElementById('redactedSoloImg');

    if (previewImg) previewImg.src = pageObj.preview_url;
    if (beforeImg) beforeImg.src = pageObj.preview_url;

    if (redactedPreviews.length >= currentPage) {
        if (afterImg) afterImg.src = redactedPreviews[currentPage - 1];
        if (soloImg) soloImg.src = redactedPreviews[currentPage - 1];
    }

    setTimeout(initCanvasDimensions, 100);
}

// Redaction Execution Pipeline
function executeRedaction() {
    const btn = document.getElementById('applyRedactBtn');
    if (!btn) return;

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Redacting & Flattening...`;

    const payload = {
        selected_detection_ids: Array.from(selectedIds),
        default_style: globalStyle,
        manual_redactions: manualRedactions
    };

    fetch(`/api/redact/${sessionData.session_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-user-shield"></i> Redact & Export Safe Copy`;

        if (!data.success) {
            alert("Redaction error: " + (data.error || "Failed to redact document."));
            return;
        }

        // Store redacted preview urls
        redactedPreviews = data.redacted_previews || [];

        // Enable view mode tabs
        const tabSplit = document.getElementById('tabSplit');
        const tabRedacted = document.getElementById('tabRedacted');
        if (tabSplit) tabSplit.style.display = 'inline-block';
        if (tabRedacted) tabRedacted.style.display = 'inline-block';

        // Update slider images
        const afterImg = document.getElementById('afterSliderImg');
        const soloImg = document.getElementById('redactedSoloImg');
        if (afterImg && redactedPreviews.length > 0) {
            afterImg.onload = () => { syncAfterImageDimensions(); };
            afterImg.src = redactedPreviews[currentPage - 1];
        }
        if (soloImg && redactedPreviews.length > 0) soloImg.src = redactedPreviews[currentPage - 1];

        // Setup download URLs
        const docBtn = document.getElementById('downloadDocBtn');
        const certBtn = document.getElementById('downloadCertBtn');
        const jsonBtn = document.getElementById('downloadJsonBtn');

        if (docBtn) docBtn.href = data.download_document_url;
        if (certBtn) certBtn.href = data.download_certificate_url;
        if (jsonBtn) jsonBtn.href = data.download_json_url;

        // Reveal bottom safe export drawer
        const drawer = document.getElementById('exportDrawer');
        if (drawer) drawer.style.display = 'block';

        // Automatically switch to Split Comparison Slider view!
        switchViewMode('split');
        setTimeout(syncAfterImageDimensions, 100);
    })
    .catch(err => {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-user-shield"></i> Redact & Export Safe Copy`;
        alert("Network error: " + err.message);
    });
}

// Switch between Original Overlay, Split Slider, and Redacted Solo
function switchViewMode(mode) {
    const overlayView = document.getElementById('overlayViewport');
    const splitView = document.getElementById('splitViewport');
    const redactedView = document.getElementById('redactedViewport');

    const tabOrig = document.getElementById('tabOriginal');
    const tabSplit = document.getElementById('tabSplit');
    const tabRed = document.getElementById('tabRedacted');

    [tabOrig, tabSplit, tabRed].forEach(t => t && t.classList.remove('active'));
    [overlayView, splitView, redactedView].forEach(v => v && (v.style.display = 'none'));

    if (mode === 'original') {
        if (overlayView) overlayView.style.display = 'inline-block';
        if (tabOrig) tabOrig.classList.add('active');
        renderBoundingBoxes();
        setupDrawingCanvas();
    } else if (mode === 'split') {
        if (splitView) splitView.style.display = 'inline-block';
        if (tabSplit) tabSplit.classList.add('active');
        syncAfterImageDimensions();
    } else if (mode === 'redacted') {
        if (redactedView) redactedView.style.display = 'inline-block';
        if (tabRed) tabRed.classList.add('active');
    }
}

// Split slider events
function syncAfterImageDimensions() {
    const beforeImg = document.getElementById('beforeSliderImg');
    const afterImg = document.getElementById('afterSliderImg');
    const container = document.querySelector('.split-image-container');
    if (beforeImg && afterImg) {
        const w = beforeImg.clientWidth || beforeImg.naturalWidth;
        const h = beforeImg.clientHeight || beforeImg.naturalHeight;
        if (w > 0 && h > 0) {
            afterImg.style.width = `${w}px`;
            afterImg.style.height = `${h}px`;
            if (container) {
                container.style.width = `${w}px`;
                container.style.height = `${h}px`;
            }
        }
    }
}

function initSplitSliderEvents() {
    const divider = document.getElementById('sliderDivider');
    const afterWrap = document.getElementById('afterWrapper');
    const container = document.querySelector('.split-image-container');

    if (!divider || !afterWrap || !container) return;

    let isSliding = false;

    divider.addEventListener('pointerdown', (e) => {
        isSliding = true;
        e.preventDefault();
    });

    window.addEventListener('pointermove', (e) => {
        if (!isSliding) return;
        const rect = container.getBoundingClientRect();
        const offsetX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
        const pct = (offsetX / rect.width) * 100;

        afterWrap.style.width = `${pct}%`;
        divider.style.left = `${pct}%`;
    });

    window.addEventListener('pointerup', () => {
        isSliding = false;
    });
}

// Purge Session Data Immediately
function purgeCurrentSession() {
    if (!sessionData) return;
    if (!confirm("Are you sure you want to permanently destroy this session and all associated files on disk?")) return;

    fetch(`/api/purge/${sessionData.session_id}`, { method: 'POST' })
    .then(r => r.json())
    .then(() => {
        window.location.href = '/';
    })
    .catch(() => {
        window.location.href = '/';
    });
}
