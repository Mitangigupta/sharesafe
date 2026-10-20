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



    if (isDrawMode) {
        canvas.classList.add('active-draw');
    } else {
        canvas.classList.remove('active-draw');
    }
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

        if (currentViewMode !== 'original') {

            switchViewMode('original');

        }

        if (btn) btn.classList.add('active');

        if (text) text.innerText = 'Exit Drawing';

        if (canvas) {

            setupDrawingCanvas();

            canvas.classList.add('active-draw');

        }

        if (typeof switchSidebarTab === 'function') switchSidebarTab('manual');

    } else {

        if (btn) btn.classList.remove('active');

        if (text) text.innerText = 'Draw Manual Box';

        if (canvas) canvas.classList.remove('active-draw');

    }

}



function updateManualRedactionsUI() {

    const list = document.getElementById('manualList');

    const count = document.getElementById('manualCount');

    if (!list || !count) return;



    const badge = document.getElementById('manualCountBadge');

    if (badge) badge.innerText = manualRedactions.length;
    try {
        if (sessionData && sessionData.session_id) {
            sessionStorage.setItem(`sharesafe_manual_${sessionData.session_id}`, JSON.stringify(manualRedactions));
        }
    } catch (e) {}



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



// Overlay visibility toggle for pure original document inspection

let isOverlayVisible = true;



function toggleOverlayVisibility() {

    isOverlayVisible = !isOverlayVisible;

    const boxLayer = document.getElementById('boxOverlayLayer');

    const drawCanvas = document.getElementById('drawingCanvas');

    const icon = document.getElementById('overlayToggleIcon');

    const text = document.getElementById('overlayToggleText');

    const btn = document.getElementById('btnToggleOverlay');

    const statusText = document.getElementById('overlayStatusText');



    if (boxLayer) boxLayer.style.display = isOverlayVisible ? 'block' : 'none';

    if (drawCanvas) drawCanvas.style.display = isOverlayVisible ? 'block' : 'none';



    if (isOverlayVisible) {

        if (icon) icon.className = 'fa-regular fa-eye-slash';

        if (text) text.innerText = 'Hide Draft Boxes';

        if (btn) btn.classList.remove('hidden-state');

        if (statusText) statusText.innerHTML = 'Original Source Document &bull; Draft Redaction Overlays Active';

    } else {

        if (icon) icon.className = 'fa-regular fa-eye';

        if (text) text.innerText = 'Show Draft Boxes';

        if (btn) btn.classList.add('hidden-state');

        if (statusText) statusText.innerHTML = 'Original Source Document &bull; Pristine Unmodified View (Overlays Hidden)';

    }

}



// Compare sub-mode toggle ('slider' or 'side-by-side')

let compareSubMode = 'slider';



function setCompareSubMode(subMode) {

    compareSubMode = subMode;

    const sliderBtn = document.getElementById('btnCompareSlider');

    const sideBtn = document.getElementById('btnCompareSide');

    const sliderContainer = document.getElementById('compareSliderContainer');

    const sideContainer = document.getElementById('compareSideContainer');

    const hint = document.getElementById('splitSliderHint');



    if (subMode === 'side-by-side') {

        if (sliderBtn) sliderBtn.classList.remove('active');

        if (sideBtn) sideBtn.classList.add('active');

        if (sliderContainer) sliderContainer.style.display = 'none';

        if (sideContainer) sideContainer.style.display = 'grid';

        if (hint) hint.innerHTML = '<i class="fa-solid fa-table-columns"></i> Side-by-side synchronized view';

        syncSideBySideImages();

    } else {

        if (sliderBtn) sliderBtn.classList.add('active');

        if (sideBtn) sideBtn.classList.remove('active');

        if (sliderContainer) sliderContainer.style.display = 'inline-block';

        if (sideContainer) sideContainer.style.display = 'none';

        if (hint) hint.innerHTML = '<i class="fa-solid fa-arrows-left-right"></i> Drag handle or use &larr; &rarr; arrow keys';

        syncAfterImageDimensions();

    }

}



function syncSideBySideImages() {

    if (!sessionData) return;

    const pageObj = sessionData.pages[currentPage - 1];

    const sideOrig = document.getElementById('sideOrigImg');

    const sideSan = document.getElementById('sideSanImg');

    if (sideOrig && pageObj) sideOrig.src = pageObj.preview_url;

    if (sideSan && redactedPreviews.length >= currentPage) {

        sideSan.src = redactedPreviews[currentPage - 1];

    }

}



// Zoom & Pan controls with synchronized scaling

function zoomCanvas(delta) {

    currentZoom = Math.max(0.5, Math.min(2.5, currentZoom + delta));

    applyZoom();

}



function resetCanvasZoom() {

    currentZoom = 1.0;

    applyZoom();

}



function applyZoom() {

    const overlayCanvas = document.getElementById('overlayCanvasWrapper') || document.querySelector('#overlayViewport .canvas-wrapper');

    const compareSlider = document.getElementById('compareSliderContainer');

    const compareSide = document.getElementById('compareSideContainer');

    const redactedCanvas = document.getElementById('redactedCanvasWrapper') || document.getElementById('redactedSoloImg');

    const ind = document.getElementById('zoomLevelIndicator');



    if (ind) ind.innerText = `${Math.round(currentZoom * 100)}%`;



    [overlayCanvas, compareSlider, compareSide, redactedCanvas].forEach(el => {

        if (el) el.style.transform = `scale(${currentZoom})`;

    });

}



// Multi-page navigation (synchronized across all viewports)

function changePage(delta) {

    if (!sessionData || sessionData.page_count <= 1) return;

    const newPage = currentPage + delta;

    if (newPage < 1 || newPage > sessionData.page_count) return;



    currentPage = newPage;

    const pageInd = document.getElementById('currentPageNum');

    if (pageInd) pageInd.innerText = currentPage;



    // Reset scroll position to top of page

    const scrollCont = document.getElementById('canvasContainer');

    if (scrollCont) scrollCont.scrollTop = 0;



    const pageObj = sessionData.pages[currentPage - 1];

    const previewImg = document.getElementById('pagePreviewImg');

    const beforeImg = document.getElementById('beforeSliderImg');

    const afterImg = document.getElementById('afterSliderImg');

    const soloImg = document.getElementById('redactedSoloImg');

    const sideOrig = document.getElementById('sideOrigImg');

    const sideSan = document.getElementById('sideSanImg');



    if (previewImg) previewImg.src = pageObj.preview_url;

    if (beforeImg) beforeImg.src = pageObj.preview_url;

    if (sideOrig) sideOrig.src = pageObj.preview_url;



    if (redactedPreviews.length >= currentPage && redactedPreviews[currentPage - 1]) {

        if (afterImg) afterImg.src = redactedPreviews[currentPage - 1];

        if (soloImg) soloImg.src = redactedPreviews[currentPage - 1];

        if (sideSan) sideSan.src = redactedPreviews[currentPage - 1];

    } else {

        // Fallback to original image so view is not blank

        if (afterImg) afterImg.src = pageObj.preview_url;

        if (soloImg) soloImg.src = pageObj.preview_url;

        if (sideSan) sideSan.src = pageObj.preview_url;

        if (currentViewMode === 'compare' || currentViewMode === 'split' || currentViewMode === 'sanitized' || currentViewMode === 'redacted') {

            debouncedAutoRedact(50);

        }

    }



    setTimeout(() => {

        initCanvasDimensions();

        syncAfterImageDimensions();

        if (compareSubMode === 'side-by-side') syncSideBySideImages();

    }, 100);

}



// Convert base64 string to Blob for direct client download
function base64ToBlob(base64, mimeType = 'application/octet-stream') {
    try {
        const cleanBase64 = base64.replace(/^data:[^;]+;base64,/, '');
        const byteCharacters = atob(cleanBase64);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        return new Blob([byteArray], { type: mimeType });
    } catch (e) {
        console.error("base64ToBlob error:", e);
        return null;
    }
}

// Re-establish session if cloud serverless container recycled
async function reestablishSession() {
    if (!sessionData) return false;
    try {
        const resp = await fetch(`/api/re-establish-session/${sessionData.session_id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_data: sessionData })
        });
        if (resp.ok) {
            showToastNotification("Session successfully restored");
            return true;
        }
    } catch (e) {}
    return false;
}

window.reestablishSessionAndRetry = async function() {
    closeRecoveryModal();
    const btn = document.getElementById('applyRedactBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Restoring Session...`;
    }
    showToastNotification("Restoring session on serverless host...");
    const ok = await reestablishSession();
    if (ok) {
        executeRedaction(() => {
            showToastNotification("Redacted document ready");
        }, false);
    } else {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> <span>Sanitize &amp; Export</span>`;
        }
        alert("Session expired on cloud host. Please re-upload or select demo sample from the home page.");
    }
};

window.openRecoveryModal = function() {
    const modal = document.getElementById('sessionRecoveryModal');
    if (modal) modal.style.display = 'flex';
};

window.closeRecoveryModal = function() {
    const modal = document.getElementById('sessionRecoveryModal');
    if (modal) modal.style.display = 'none';
};

// Redaction Execution Pipeline with Serverless Auto-Recovery & Base64 Fallback
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
        session_id: sessionData.session_id,
        session_data: sessionData, // Transmit session data for stateless container re-hydration
        selected_detection_ids: Array.from(selectedIds),
        default_style: globalStyle,
        manual_redactions: manualRedactions
    };

    fetch(`/api/redact/${sessionData.session_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
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
            const isSessionErr = r.status === 404 || (data && data.session_expired);
            const errObj = new Error((data && data.error) ? data.error : `Server error (${r.status} ${r.statusText})`);
            errObj.isSessionExpired = isSessionErr;
            throw errObj;
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

        // Use base64 data URIs if returned to avoid network round-trip delays on serverless
        if (data.redacted_previews_data && data.redacted_previews_data.length > 0) {
            redactedPreviews = data.redacted_previews_data;
        } else {
            const cacheBuster = Date.now();
            redactedPreviews = (data.redacted_previews || []).map(url => `${url}?t=${cacheBuster}`);
        }

        // Enable view mode tabs
        const tabSplit = document.getElementById('tabSplit') || document.getElementById('tabCompare');
        const tabRedacted = document.getElementById('tabRedacted') || document.getElementById('tabSanitized');
        if (tabSplit) tabSplit.style.display = 'inline-flex';
        if (tabRedacted) tabRedacted.style.display = 'inline-flex';

        // Update slider and solo preview images
        const afterImg = document.getElementById('afterSliderImg');
        const soloImg = document.getElementById('redactedSoloImg');
        const sideSanImg = document.getElementById('sideSanImg');

        if (afterImg && redactedPreviews.length >= currentPage) {
            afterImg.onload = () => { syncAfterImageDimensions(); };
            afterImg.src = redactedPreviews[currentPage - 1];
        }
        if (soloImg && redactedPreviews.length >= currentPage) {
            soloImg.src = redactedPreviews[currentPage - 1];
        }
        if (sideSanImg && redactedPreviews.length >= currentPage) {
            sideSanImg.src = redactedPreviews[currentPage - 1];
        }

        // Setup download URLs with direct Client Blob generation
        const docBtn = document.getElementById('downloadDocBtn');
        const certBtn = document.getElementById('downloadCertBtn');
        const jsonBtn = document.getElementById('downloadJsonBtn');

        if (docBtn) {
            if (data.document_base64) {
                const mime = data.mime_type || (sessionData.is_pdf ? 'application/pdf' : 'image/png');
                const docBlob = base64ToBlob(data.document_base64, mime);
                if (docBlob) {
                    docBtn.href = URL.createObjectURL(docBlob);
                    docBtn.download = data.download_filename || `safe_${sessionData.file_name}`;
                } else {
                    docBtn.href = data.download_document_url;
                }
            } else {
                docBtn.href = data.download_document_url;
            }
        }

        if (certBtn) {
            if (data.certificate_base64) {
                const certBlob = base64ToBlob(data.certificate_base64, 'application/pdf');
                if (certBlob) {
                    certBtn.href = URL.createObjectURL(certBlob);
                    certBtn.download = `ShareSafe_Certificate_${sessionData.session_id.slice(0, 8)}.pdf`;
                } else {
                    certBtn.href = data.download_certificate_url;
                }
            } else {
                certBtn.href = data.download_certificate_url;
            }
        }

        if (jsonBtn) {
            if (data.audit_data) {
                const jsonBlob = new Blob([JSON.stringify(data.audit_data, null, 2)], { type: 'application/json' });
                jsonBtn.href = URL.createObjectURL(jsonBlob);
                jsonBtn.download = `ShareSafe_Audit_${sessionData.session_id.slice(0, 8)}.json`;
            } else {
                jsonBtn.href = data.download_json_url;
            }
        }

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
    .catch(async err => {
        isRedacting = false;
        showUpdatingBadge(false);
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> <span>Sanitize &amp; Export</span>`;
        }

        // Auto-recover session if serverless container recycled
        if (err.isSessionExpired) {
            if (!isAuto) {
                const restored = await reestablishSession();
                if (restored) {
                    executeRedaction(callback, false);
                    return;
                }
                openRecoveryModal();
            }
            return;
        }

        if (!isAuto) {
            alert("Network error: " + err.message);
        }
    });
}

// Switch between 3 Modes: Interactive Overlay, Before / After Split, and Sanitized Result
function switchViewMode(mode) {
    // Map mode and aliases
    const normalizedMode = (mode === 'split' || mode === 'compare') ? 'split' : ((mode === 'redacted' || mode === 'sanitized') ? 'redacted' : 'original');

    currentViewMode = normalizedMode;

    const overlayView = document.getElementById('overlayViewport');
    const splitView = document.getElementById('splitViewport');
    const redactedView = document.getElementById('redactedViewport');

    const tabOrig = document.getElementById('tabOriginal');
    const tabSplit = document.getElementById('tabSplit') || document.getElementById('tabCompare');
    const tabRed = document.getElementById('tabRedacted') || document.getElementById('tabSanitized');

    // Immediately update tab states so controls are fully responsive
    [tabOrig, tabSplit, tabRed].forEach(t => {
        if (t) {
            t.classList.remove('active');
            t.setAttribute('aria-selected', 'false');
        }
    });
    [overlayView, splitView, redactedView].forEach(v => v && (v.style.display = 'none'));

    if (normalizedMode === 'original') {
        if (overlayView) overlayView.style.display = 'flex';
        if (tabOrig) {
            tabOrig.classList.add('active');
            tabOrig.setAttribute('aria-selected', 'true');
        }
        renderBoundingBoxes();
        setupDrawingCanvas();
    } else if (normalizedMode === 'split') {
        if (splitView) splitView.style.display = 'flex';
        if (tabSplit) {
            tabSplit.classList.add('active');
            tabSplit.setAttribute('aria-selected', 'true');
        }
        if (compareSubMode === 'side-by-side') {
            syncSideBySideImages();
        } else {
            syncAfterImageDimensions();
        }
    } else if (normalizedMode === 'redacted') {
        if (redactedView) redactedView.style.display = 'flex';
        if (tabRed) {
            tabRed.classList.add('active');
            tabRed.setAttribute('aria-selected', 'true');
        }
        const soloImg = document.getElementById('redactedSoloImg');
        if (soloImg && redactedPreviews.length >= currentPage) {
            soloImg.src = redactedPreviews[currentPage - 1];
        }
    }

    // If switching to split or redacted and preview not ready or dirty, generate in background
    if ((normalizedMode === 'split' || normalizedMode === 'redacted') && (isDirty || redactedPreviews.length === 0)) {
        debouncedAutoRedact(50);
    }
}

// Split slider events & interactive comparison logic

let currentSliderPct = 50;



function setSliderPct(pct) {

    currentSliderPct = Math.max(0, Math.min(100, pct));

    const afterWrap = document.getElementById('afterWrapper');

    const divider = document.getElementById('sliderDivider');



    if (afterWrap) {

        // Reveal Sanitized Copy on the LEFT (0% to currentSliderPct%):

        afterWrap.style.clipPath = `polygon(0% 0%, ${currentSliderPct}% 0%, ${currentSliderPct}% 100%, 0% 100%)`;

        afterWrap.style.webkitClipPath = `polygon(0% 0%, ${currentSliderPct}% 0%, ${currentSliderPct}% 100%, 0% 100%)`;

    }

    if (divider) {

        divider.style.left = `${currentSliderPct}%`;

        divider.setAttribute('aria-valuenow', Math.round(currentSliderPct));

    }



    // Adapt floating pills visibility when slider handle approaches the corners

    const leftPill = document.querySelector('.floating-side-pill.pill-left');

    const rightPill = document.querySelector('.floating-side-pill.pill-right');

    if (leftPill) leftPill.style.opacity = currentSliderPct < 15 ? '0.35' : '1';

    if (rightPill) rightPill.style.opacity = currentSliderPct > 85 ? '0.35' : '1';

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

        divider.setPointerCapture?.(e.pointerId);

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



    window.addEventListener('pointerup', (e) => {

        if (isSliding) {

            isSliding = false;

            divider.releasePointerCapture?.(e.pointerId);

        }

    });



    window.addEventListener('pointercancel', () => {

        isSliding = false;

    });



    // Keyboard accessibility for divider slider

    divider.addEventListener('keydown', (e) => {

        if (e.key === 'ArrowLeft') {

            setSliderPct(currentSliderPct - 3);

            e.preventDefault();

        } else if (e.key === 'ArrowRight') {

            setSliderPct(currentSliderPct + 3);

            e.preventDefault();

        } else if (e.key === 'Home') {

            setSliderPct(0);

            e.preventDefault();

        } else if (e.key === 'End') {

            setSliderPct(100);

            e.preventDefault();

        }

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

