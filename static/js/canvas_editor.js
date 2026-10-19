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
let isDirty = true;
let currentViewMode = 'original';
let autoRedactTimer = null;
let isRedacting = false;
let pendingRedact = false;

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
    updateSidebarSelectedCount();

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
    const searchQuery = (window.currentSearchQuery || '').toLowerCase().trim();

    // 1. Render automated detections for this page
    const pageDets = sessionData.detections.filter(d => (d.page || 1) === currentPage);

    pageDets.forEach(d => {
        if (!d.bbox || d.bbox.length !== 4) return;
        const [x, y, w, h] = d.bbox;

        const isMatch = !searchQuery || 
            (d.label || '').toLowerCase().includes(searchQuery) ||
            (d.category || '').toLowerCase().includes(searchQuery) ||
            (d.masked || '').toLowerCase().includes(searchQuery) ||
            (d.risk || '').toLowerCase().includes(searchQuery);

        const box = document.createElement('div');
        box.id = `box-${d.id}`;
        box.className = `box-overlay box-${d.risk.toLowerCase()} box-style-${globalStyle}`;
        if (!selectedIds.has(d.id)) {
            box.classList.add('deselected');
        }
        if (searchQuery && !isMatch) {
            box.classList.add('search-filtered-out');
        }

        box.style.left = `${x * scaleX}px`;
        box.style.top = `${y * scaleY}px`;
        box.style.width = `${w * scaleX}px`;
        box.style.height = `${h * scaleY}px`;
        box.title = `${d.label}: ${d.masked} (${d.risk} Risk) — Click to Toggle Redaction`;

        // Stamp style label inside box
        if (selectedIds.has(d.id) && globalStyle === 'stamp') {
            const shortLabel = (d.label && d.label.length <= 10) ? `[${d.label.toUpperCase()}]` : '[REDACTED]';
            box.innerHTML = `<span class="stamp-inner-text">${escapeHtml(shortLabel)}</span>`;
        }

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
        const mStyle = m.style || globalStyle;
        const box = document.createElement('div');
        box.id = `box-${m.id}`;
        box.className = `box-overlay box-manual box-style-${mStyle}`;
        box.style.left = `${x * scaleX}px`;
        box.style.top = `${y * scaleY}px`;
        box.style.width = `${w * scaleX}px`;
        box.style.height = `${h * scaleY}px`;
        box.title = `Manual Redaction: ${m.label}`;

        if (mStyle === 'stamp') {
            box.innerHTML = `<span class="stamp-inner-text">[REDACTED]</span>`;
        }

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
        ctx.strokeStyle = '#C96D67';
        ctx.lineWidth = 2;
        ctx.fillStyle = 'rgba(201, 109, 103, 0.22)';

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
        notifySelectionChanged();
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
    notifySelectionChanged();
}

function updateSidebarSelectedCount() {
    const hint = document.getElementById('selectedCountHint');
    if (hint && sessionData && sessionData.detections) {
        const total = sessionData.detections.length;
        const selectedCount = sessionData.detections.filter(d => selectedIds.has(d.id)).length;
        hint.innerText = `${selectedCount} of ${total} selected`;
    }
}

function notifySelectionChanged() {
    isDirty = true;
    renderBoundingBoxes();
    updateSidebarSelectedCount();

    // If currently viewing split or redacted mode, auto-update the sanitized preview
    if (currentViewMode === 'split' || currentViewMode === 'redacted') {
        debouncedAutoRedact(250);
    }
}

function debouncedAutoRedact(delay = 250) {
    clearTimeout(autoRedactTimer);
    showUpdatingBadge(true);
    autoRedactTimer = setTimeout(() => {
        executeRedaction(() => {
            showUpdatingBadge(false);
        }, true);
    }, delay);
}

function showUpdatingBadge(show) {
    const badge = document.getElementById('previewStatusBadge');
    if (!badge) return;
    if (show) {
        badge.style.display = 'inline-flex';
        badge.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>Updating preview...</span>`;
    } else {
        badge.innerHTML = `<i class="fa-solid fa-check text-sage"></i> <span>Preview updated</span>`;
        setTimeout(() => {
            if (!isRedacting && badge) badge.style.display = 'none';
        }, 1200);
    }
}

// Detection toggles and selections
function toggleDetection(id) {
    if (selectedIds.has(id)) {
        selectedIds.delete(id);
    } else {
        selectedIds.add(id);
    }
    syncCheckbox(id);
    notifySelectionChanged();
}

window.setDetectionSelected = function(id, isSelected) {
    if (isSelected) selectedIds.add(id);
    else selectedIds.delete(id);
    syncCheckbox(id);
    notifySelectionChanged();
};

function onCheckboxChange(id) {
    const chk = document.getElementById(`chk-${id}`);
    if (chk) {
        if (chk.checked) selectedIds.add(id);
        else selectedIds.delete(id);
    }
    notifySelectionChanged();
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
    notifySelectionChanged();
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
    notifySelectionChanged();
}

function deselectAllDetections() {
    selectedIds.clear();
    document.querySelectorAll('.det-checkbox').forEach(c => c.checked = false);
    notifySelectionChanged();
}

function updateGlobalStyle(newStyle) {
    globalStyle = newStyle;
    // Update style on all manual redactions
    manualRedactions.forEach(m => m.style = newStyle);
    // Update style badge labels in detection items
    updateDetectionsStyleLabels(newStyle);
    // Display executive toast notification
    showToastNotification(`Redaction Style: ${getStyleDisplayName(newStyle)} applied`);
    // Re-render bounding boxes and sync with sanitized view
    notifySelectionChanged();
}

function getStyleDisplayName(style) {
    const map = {
        'blackout': 'Solid Blackout (100% Black)',
        'whiteout': 'Clean Whiteout (100% White)',
        'blur': 'Gaussian Blur (Deep Bokeh)',
        'pixelate': 'Mosaic Pixelate (Vector Grid)',
        'stamp': 'Redacted Stamp (Obsidian & Coral)'
    };
    return map[style] || style;
}

function updateDetectionsStyleLabels(style) {
    const shortNames = {
        'blackout': 'Blackout',
        'whiteout': 'Whiteout',
        'blur': 'Blur',
        'pixelate': 'Pixelate',
        'stamp': 'Stamp'
    };
    const name = shortNames[style] || style;
    document.querySelectorAll('.style-name-text').forEach(el => {
        el.innerText = name;
    });
}

function showToastNotification(msg) {
    let toast = document.getElementById('studioToast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'studioToast';
        toast.className = 'studio-toast';
        document.body.appendChild(toast);
    }
    toast.innerHTML = `<i class="fa-solid fa-circle-check text-sage"></i> <span>${escapeHtml(msg)}</span>`;
    toast.classList.add('visible');
    clearTimeout(window._toastTimeout);
    window._toastTimeout = setTimeout(() => {
        toast.classList.remove('visible');
    }, 2500);
}

// Global Nav Search Filter across detections & canvas
window.handleNavSearch = function(query) {
    window.currentSearchQuery = query;
    const items = document.querySelectorAll('.detection-item');
    const q = (query || '').toLowerCase().trim();

    items.forEach(item => {
        const text = item.innerText.toLowerCase();
        if (!q || text.includes(q)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });

    renderBoundingBoxes();
};

// Item click handler (toggles checkbox on row click unless button clicked)
window.handleDetectionItemClick = function(event, id) {
    if (event.target.closest('.btn-threat-inspect') || event.target.closest('.custom-toggle')) {
        return;
    }
    toggleDetection(id);
};

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
function executeRedaction(callback, isAuto = false) {
    if (isRedacting) {
        pendingRedact = true;
        return;
    }
    isRedacting = true;
    showUpdatingBadge(true);

    const btn = document.getElementById('applyRedactBtn');
    if (btn && !isAuto) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Redacting & Flattening...`;
    }

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
    .then(async r => {
        let data = null;
        try {
            data = await r.json();
        } catch (e) {
            data = null;
        }
        if (!r.ok) {
            const msg = (data && data.error) ? data.error : `Server error (${r.status} ${r.statusText})`;
            throw new Error(msg);
        }
        return data || {};
    })
    .then(data => {
        isRedacting = false;
        isDirty = false;

        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> <span>Sanitize &amp; Export</span>`;
        }

        if (!data.success) {
            showUpdatingBadge(false);
            if (!isAuto) alert("Redaction error: " + (data.error || "Failed to redact document."));
            return;
        }

        // Cache-busted preview URLs to guarantee immediate DOM refresh
        const cacheBuster = Date.now();
        redactedPreviews = (data.redacted_previews || []).map(url => `${url}?t=${cacheBuster}`);

        // Enable view mode tabs
        const tabSplit = document.getElementById('tabSplit');
        const tabRedacted = document.getElementById('tabRedacted');
        if (tabSplit) tabSplit.style.display = 'inline-flex';
        if (tabRedacted) tabRedacted.style.display = 'inline-flex';

        // Update slider and solo preview images with cache-busted URLs
        const afterImg = document.getElementById('afterSliderImg');
        const soloImg = document.getElementById('redactedSoloImg');
        if (afterImg && redactedPreviews.length >= currentPage) {
            afterImg.onload = () => { syncAfterImageDimensions(); };
            afterImg.src = redactedPreviews[currentPage - 1];
        }
        if (soloImg && redactedPreviews.length >= currentPage) {
            soloImg.src = redactedPreviews[currentPage - 1];
        }

        // Setup download URLs
        const docBtn = document.getElementById('downloadDocBtn');
        const certBtn = document.getElementById('downloadCertBtn');
        const jsonBtn = document.getElementById('downloadJsonBtn');

        if (docBtn) docBtn.href = data.download_document_url;
        if (certBtn) certBtn.href = data.download_certificate_url;
        if (jsonBtn) jsonBtn.href = data.download_json_url;

        // If manual click on Sanitize & Export, reveal bottom export drawer and toast
        if (!isAuto) {
            const drawer = document.getElementById('exportDrawer');
            if (drawer) drawer.style.display = 'block';
            showToastNotification("Document Sanitized & Cryptographically Sealed");
        }

        showUpdatingBadge(false);

        if (pendingRedact) {
            pendingRedact = false;
            debouncedAutoRedact(50);
        } else if (typeof callback === 'function') {
            callback();
        } else if (!isAuto) {
            switchViewMode('split');
            setTimeout(syncAfterImageDimensions, 100);
        }
    })
    .catch(err => {
        isRedacting = false;
        showUpdatingBadge(false);
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> <span>Sanitize &amp; Export</span>`;
        }
        if (!isAuto) {
            alert("Network error: " + err.message);
        }
    });
}

// Switch between Original Overlay, Split Slider, and Redacted Solo
function switchViewMode(mode) {
    if ((mode === 'split' || mode === 'redacted') && (isDirty || redactedPreviews.length === 0)) {
        showToastNotification("Generating sanitized copy for comparison...");
        executeRedaction(() => {
            switchViewMode(mode);
        });
        return;
    }

    currentViewMode = mode;

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
let currentSliderPct = 50;

function setSliderPct(pct) {
    currentSliderPct = Math.max(0, Math.min(100, pct));
    const afterWrap = document.getElementById('afterWrapper');
    const divider = document.getElementById('sliderDivider');
    if (afterWrap) {
        // Reveal Sanitized Copy on the LEFT (0% to pct%):
        afterWrap.style.clipPath = `polygon(0% 0%, ${currentSliderPct}% 0%, ${currentSliderPct}% 100%, 0% 100%)`;
        afterWrap.style.webkitClipPath = `polygon(0% 0%, ${currentSliderPct}% 0%, ${currentSliderPct}% 100%, 0% 100%)`;
    }
    if (divider) {
        divider.style.left = `${currentSliderPct}%`;
    }
}

function syncAfterImageDimensions() {
    // Sizing is automatically and responsively handled by CSS (100% overlay)
    setSliderPct(currentSliderPct);
}

function initSplitSliderEvents() {
    const divider = document.getElementById('sliderDivider');
    const container = document.querySelector('.split-image-container');

    if (!divider || !container) return;

    let isSliding = false;

    function updateSlider(clientX) {
        const rect = container.getBoundingClientRect();
        if (rect.width <= 0) return;
        const offsetX = Math.max(0, Math.min(clientX - rect.left, rect.width));
        const pct = (offsetX / rect.width) * 100;
        setSliderPct(pct);
    }

    divider.addEventListener('pointerdown', (e) => {
        isSliding = true;
        e.preventDefault();
    });

    container.addEventListener('pointerdown', (e) => {
        isSliding = true;
        updateSlider(e.clientX);
        e.preventDefault();
    });

    window.addEventListener('pointermove', (e) => {
        if (!isSliding) return;
        updateSlider(e.clientX);
    });

    window.addEventListener('pointerup', () => {
        isSliding = false;
    });

    window.addEventListener('pointercancel', () => {
        isSliding = false;
    });

    setSliderPct(50);
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
