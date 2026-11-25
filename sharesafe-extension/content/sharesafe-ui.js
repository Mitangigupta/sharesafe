/**
 * ShareSafe Chrome Extension — Unified UI Design System
 *
 * Shared, spacious, cybersecurity-grade UI components for both WhatsApp Web and Gmail.
 * Ensures consistent typography, spacing, status indicators, SVG iconography, and
 * clear user-first messaging across all scan states (scanning, verified, threat, offline, unsupported).
 */

(function () {
  if (window.ShareSafeUI) return;

  const FONT_STACK = "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
  const MONO_STACK = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";

  const TOKENS = {
    bgCard: "#FFFFFF",
    bgSubtle: "#F8FAFC",
    bgMuted: "#F1F5F9",
    border: "#E2E8F0",
    borderSubtle: "#EEF2F6",
    inkPrimary: "#0F172A",
    inkSecondary: "#475569",
    inkMuted: "#64748B",
    brandAccent: "#C65A4A",
    brandAccentHover: "#B24B3C",
    brandTint: "#FDF2F0",
    brandBorder: "#F5D0CA",
    infoBg: "#EFF6FF",
    infoBorder: "#BFDBFE",
    infoInk: "#1D4ED8",
    safeBg: "#F0FDF4",
    safeBorder: "#BBF7D0",
    safeInk: "#15803D",
    warnBg: "#FFFBEB",
    warnBorder: "#FDE68A",
    warnInk: "#B45309",
    dangerBg: "#FEF2F2",
    dangerBorder: "#FECACA",
    dangerInk: "#B91C1C",
    shadowCard: "0 10px 30px rgba(15, 23, 42, 0.12), 0 2px 8px rgba(15, 23, 42, 0.06)",
    shadowModal: "0 24px 60px rgba(15, 23, 42, 0.24), 0 4px 16px rgba(15, 23, 42, 0.08)"
  };

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  function ensureStyles() {
    if (document.getElementById("sharesafe-ui-styles")) return;
    const style = document.createElement("style");
    style.id = "sharesafe-ui-styles";
    style.textContent = `
      @keyframes ssUiSpin {
        to { transform: rotate(360deg); }
      }
      @keyframes ssUiSlideUp {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @keyframes ssUiFadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      .ss-ui-btn-primary:hover {
        filter: brightness(0.95);
      }
      .ss-ui-btn-secondary:hover {
        background: #F1F5F9 !important;
      }
      .ss-ui-btn-ghost:hover {
        color: #0F172A !important;
        background: #F8FAFC !important;
      }
      .ss-ui-details-toggle::-webkit-details-marker {
        display: none;
      }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  const ICONS = {
    shield: (color = TOKENS.brandAccent, size = 20) => `
      <svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:block;flex-shrink:0;">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    `,
    shieldCheck: (color = TOKENS.safeInk, size = 20) => `
      <svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:block;flex-shrink:0;">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    `,
    shieldAlert: (color = TOKENS.warnInk, size = 20) => `
      <svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:block;flex-shrink:0;">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    `,
    serverOff: (color = TOKENS.dangerInk, size = 20) => `
      <svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:block;flex-shrink:0;">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="9.5" y1="9.5" x2="14.5" y2="14.5"/>
        <line x1="14.5" y1="9.5" x2="9.5" y2="14.5"/>
      </svg>
    `,
    close: (color = TOKENS.inkMuted, size = 16) => `
      <svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:block;">
        <line x1="18" y1="6" x2="6" y2="18"/>
        <line x1="6" y1="6" x2="18" y2="18"/>
      </svg>
    `
  };

  function removeFloatingCards() {
    const existingToast = document.getElementById("sharesafe-status-toast");
    if (existingToast) existingToast.remove();
    const existingCard = document.getElementById("sharesafe-floating-status");
    if (existingCard) existingCard.remove();
  }

  /**
   * Spacious non-blocking status card shown while an attachment is being scanned.
   */
  function showScanningCard(file) {
    ensureStyles();
    removeFloatingCards();

    const card = document.createElement("div");
    card.id = "sharesafe-floating-status";
    card.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 2147483647;
      width: 380px;
      max-width: calc(100vw - 32px);
      background: ${TOKENS.bgCard};
      border: 1px solid ${TOKENS.border};
      border-radius: 14px;
      box-shadow: ${TOKENS.shadowCard};
      padding: 18px 20px;
      box-sizing: border-box;
      font-family: ${FONT_STACK};
      animation: ssUiSlideUp 0.22s ease;
    `;

    card.innerHTML = `
      <div style="display: flex; align-items: flex-start; gap: 14px;">
        <div style="width: 40px; height: 40px; border-radius: 10px; background: ${TOKENS.infoBg}; border: 1px solid ${TOKENS.infoBorder}; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
          <div style="width: 18px; height: 18px; border: 2.5px solid ${TOKENS.infoBorder}; border-top-color: ${TOKENS.infoInk}; border-radius: 50%; animation: ssUiSpin 0.75s linear infinite;"></div>
        </div>
        <div style="flex: 1; min-width: 0;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 4px;">
            <span style="font-size: 14px; font-weight: 700; color: ${TOKENS.inkPrimary}; letter-spacing: -0.01em;">
              Scanning attachment...
            </span>
            <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: ${TOKENS.infoInk}; background: ${TOKENS.infoBg}; border: 1px solid ${TOKENS.infoBorder}; padding: 2px 8px; border-radius: 999px;">
              ShareSafe
            </span>
          </div>
          <div style="font-size: 13px; color: ${TOKENS.inkSecondary}; line-height: 1.45; margin-bottom: 8px;">
            Inspecting for sensitive data, credentials, and hidden metadata locally.
          </div>
          <div style="font-size: 12px; color: ${TOKENS.inkMuted}; background: ${TOKENS.bgSubtle}; border: 1px solid ${TOKENS.borderSubtle}; border-radius: 8px; padding: 7px 10px; display: flex; align-items: center; justify-content: space-between; gap: 8px;">
            <span style="font-weight: 600; color: ${TOKENS.inkPrimary}; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(file.name)}</span>
            <span style="flex-shrink: 0;">${formatBytes(file.size)}</span>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(card);
    return card;
  }

  /**
   * Spacious non-blocking success card shown when an attachment passes verification.
   */
  function showVerifiedCard(file, duration = 3200) {
    ensureStyles();
    removeFloatingCards();

    const card = document.createElement("div");
    card.id = "sharesafe-floating-status";
    card.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 2147483647;
      width: 380px;
      max-width: calc(100vw - 32px);
      background: ${TOKENS.bgCard};
      border: 1px solid ${TOKENS.safeBorder};
      border-radius: 14px;
      box-shadow: ${TOKENS.shadowCard};
      padding: 18px 20px;
      box-sizing: border-box;
      font-family: ${FONT_STACK};
      animation: ssUiSlideUp 0.22s ease;
    `;

    card.innerHTML = `
      <div style="display: flex; align-items: flex-start; gap: 14px;">
        <div style="width: 40px; height: 40px; border-radius: 10px; background: ${TOKENS.safeBg}; border: 1px solid ${TOKENS.safeBorder}; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
          ${ICONS.shieldCheck(TOKENS.safeInk, 20)}
        </div>
        <div style="flex: 1; min-width: 0;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 4px;">
            <span style="font-size: 14px; font-weight: 700; color: ${TOKENS.inkPrimary}; letter-spacing: -0.01em;">
              Attachment Verified
            </span>
            <button type="button" id="ssCardClose" aria-label="Dismiss" style="background: none; border: none; padding: 2px; cursor: pointer; color: ${TOKENS.inkMuted}; border-radius: 4px;">
              ${ICONS.close(TOKENS.inkMuted, 15)}
            </button>
          </div>
          <div style="font-size: 13px; color: ${TOKENS.inkSecondary}; line-height: 1.45; margin-bottom: 8px;">
            ShareSafe has completed the security scan. No sensitive data or threats were detected.
          </div>
          <div style="font-size: 12px; color: ${TOKENS.safeInk}; background: ${TOKENS.safeBg}; border: 1px solid ${TOKENS.safeBorder}; border-radius: 8px; padding: 6px 10px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${escapeHtml(file.name)}
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(card);

    const closeBtn = card.querySelector("#ssCardClose");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => card.remove());
    }

    if (duration > 0) {
      setTimeout(() => {
        if (card.parentElement) {
          card.style.opacity = "0";
          card.style.transition = "opacity 0.25s ease";
          setTimeout(() => card.remove(), 250);
        }
      }, duration);
    }
    return card;
  }

  /**
   * Clean floating notification toast for action confirmations.
   */
  function showToast(message, type = "info", duration = 3200) {
    ensureStyles();
    removeFloatingCards();

    const palette = type === "error"
      ? { bg: TOKENS.dangerBg, border: TOKENS.dangerBorder, ink: TOKENS.dangerInk, icon: ICONS.shieldAlert(TOKENS.dangerInk, 18) }
      : type === "success"
      ? { bg: TOKENS.safeBg, border: TOKENS.safeBorder, ink: TOKENS.safeInk, icon: ICONS.shieldCheck(TOKENS.safeInk, 18) }
      : { bg: TOKENS.bgCard, border: TOKENS.border, ink: TOKENS.inkPrimary, icon: ICONS.shield(TOKENS.brandAccent, 18) };

    const toast = document.createElement("div");
    toast.id = "sharesafe-status-toast";
    toast.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 2147483647;
      max-width: 400px;
      padding: 14px 18px;
      background: ${palette.bg};
      color: ${palette.ink};
      border: 1px solid ${palette.border};
      border-radius: 12px;
      box-shadow: ${TOKENS.shadowCard};
      font-family: ${FONT_STACK};
      font-size: 13px;
      font-weight: 500;
      line-height: 1.45;
      display: flex;
      align-items: center;
      gap: 12px;
      animation: ssUiSlideUp 0.22s ease;
      pointer-events: none;
    `;

    toast.innerHTML = `
      ${palette.icon}
      <span>${escapeHtml(message)}</span>
    `;

    document.body.appendChild(toast);

    if (duration > 0) {
      setTimeout(() => {
        if (toast.parentElement) {
          toast.style.opacity = "0";
          toast.style.transition = "opacity 0.25s ease";
          setTimeout(() => toast.remove(), 250);
        }
      }, duration);
    }
    return toast;
  }

  /**
   * Shared spacious modal shell for Offline / Scan Unavailable and Unsupported Format states.
   */
  function createNoticeModal({
    badgeText,
    badgeColors,
    iconHtml,
    iconBg,
    iconBorder,
    title,
    subtitle,
    whatHappenedHtml,
    guidanceText,
    detailsTitle,
    detailsHtml,
    primaryLabel,
    primaryBg,
    overrideLabel,
    onCancel,
    onOverride,
    cancelToastMessage,
    overrideToastMessage
  }) {
    ensureStyles();
    const existing = document.getElementById("sharesafe-shield-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "sharesafe-shield-overlay";
    overlay.style.cssText = `
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(15, 23, 42, 0.56);
      backdrop-filter: blur(4px);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      box-sizing: border-box;
      font-family: ${FONT_STACK};
      animation: ssUiFadeIn 0.18s ease;
    `;

    overlay.innerHTML = `
      <div style="
        background: ${TOKENS.bgCard};
        border-radius: 16px;
        width: 100%;
        max-width: 520px;
        box-shadow: ${TOKENS.shadowModal};
        border: 1px solid ${TOKENS.border};
        overflow: hidden;
        box-sizing: border-box;
      ">
        <!-- Branded Header -->
        <div style="
          padding: 20px 26px;
          background: ${TOKENS.bgSubtle};
          border-bottom: 1px solid ${TOKENS.border};
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
        ">
          <div style="display: flex; align-items: center; gap: 14px; min-width: 0;">
            <div style="
              width: 42px;
              height: 42px;
              border-radius: 11px;
              background: ${iconBg};
              border: 1px solid ${iconBorder};
              display: flex;
              align-items: center;
              justify-content: center;
              flex-shrink: 0;
            ">
              ${iconHtml}
            </div>
            <div style="min-width: 0;">
              <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 2px;">
                <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: ${TOKENS.brandAccent};">
                  ShareSafe
                </span>
                <span style="font-size: 11px; color: ${TOKENS.inkMuted};">&bull;</span>
                <span style="font-size: 11px; font-weight: 500; color: ${TOKENS.inkMuted};">
                  ${escapeHtml(subtitle)}
                </span>
              </div>
              <div style="font-size: 17px; font-weight: 700; color: ${TOKENS.inkPrimary}; letter-spacing: -0.015em; line-height: 1.3;">
                ${escapeHtml(title)}
              </div>
            </div>
          </div>

          <span style="
            font-size: 11px;
            font-weight: 700;
            padding: 4px 11px;
            border-radius: 999px;
            background: ${badgeColors.bg};
            color: ${badgeColors.ink};
            border: 1px solid ${badgeColors.border};
            letter-spacing: 0.3px;
            white-space: nowrap;
            flex-shrink: 0;
          ">
            ${escapeHtml(badgeText)}
          </span>
        </div>

        <!-- Spacious Body: What happened -> Why -> What to do -->
        <div style="padding: 26px 26px 24px 26px;">
          <p style="margin: 0 0 18px 0; font-size: 14px; color: ${TOKENS.inkPrimary}; line-height: 1.6;">
            ${whatHappenedHtml}
          </p>

          <div style="
            background: ${TOKENS.bgSubtle};
            border: 1px solid ${TOKENS.border};
            border-radius: 12px;
            padding: 14px 16px;
            margin-bottom: 20px;
          ">
            <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: ${TOKENS.inkMuted}; margin-bottom: 6px;">
              Recommended Action
            </div>
            <div style="font-size: 13px; color: ${TOKENS.inkSecondary}; line-height: 1.55;">
              ${escapeHtml(guidanceText)}
            </div>
          </div>

          <!-- Secondary Technical / Format Details -->
          <details style="
            background: ${TOKENS.bgMuted};
            border: 1px solid ${TOKENS.borderSubtle};
            border-radius: 10px;
            padding: 10px 14px;
            margin-bottom: 24px;
          ">
            <summary class="ss-ui-details-toggle" style="
              font-size: 12px;
              font-weight: 600;
              color: ${TOKENS.inkSecondary};
              cursor: pointer;
              display: flex;
              align-items: center;
              justify-content: space-between;
              list-style: none;
              user-select: none;
            ">
              <span>${escapeHtml(detailsTitle)}</span>
              <span style="font-size: 11px; color: ${TOKENS.inkMuted};">View details</span>
            </summary>
            <div style="
              margin-top: 10px;
              padding-top: 10px;
              border-top: 1px solid ${TOKENS.border};
              font-size: 12px;
              color: ${TOKENS.inkMuted};
              line-height: 1.55;
            ">
              ${detailsHtml}
            </div>
          </details>

          <!-- Comfortable Action Buttons -->
          <div style="display: flex; flex-direction: column; gap: 10px;">
            <button id="ssBtnCancel" type="button" class="ss-ui-btn-primary" style="
              width: 100%;
              height: 44px;
              padding: 0 20px;
              background: ${primaryBg};
              color: #FFFFFF;
              border: none;
              border-radius: 10px;
              font-family: ${FONT_STACK};
              font-size: 14px;
              font-weight: 600;
              cursor: pointer;
              display: flex;
              align-items: center;
              justify-content: center;
              gap: 8px;
              transition: filter 0.15s ease;
            ">
              ${escapeHtml(primaryLabel)}
            </button>
            <button id="ssBtnOverride" type="button" class="ss-ui-btn-ghost" style="
              width: 100%;
              min-height: 38px;
              padding: 8px 14px;
              background: transparent;
              border: 1px solid transparent;
              border-radius: 8px;
              color: ${TOKENS.inkMuted};
              font-family: ${FONT_STACK};
              font-size: 13px;
              font-weight: 500;
              cursor: pointer;
              text-align: center;
              transition: background 0.15s ease, color 0.15s ease;
            ">
              ${escapeHtml(overrideLabel)}
            </button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector("#ssBtnCancel").addEventListener("click", () => {
      overlay.remove();
      if (typeof onCancel === "function") onCancel();
      if (cancelToastMessage) showToast(cancelToastMessage, "info");
    });

    overlay.querySelector("#ssBtnOverride").addEventListener("click", () => {
      overlay.remove();
      if (typeof onOverride === "function") onOverride();
      if (overrideToastMessage) showToast(overrideToastMessage, "info");
    });
  }

  function showOfflineModal(file, errMsg, onCancel, onOverride) {
    createNoticeModal({
      badgeText: "Scan Unavailable",
      badgeColors: { bg: TOKENS.dangerBg, ink: TOKENS.dangerInk, border: TOKENS.dangerBorder },
      iconHtml: ICONS.serverOff(TOKENS.dangerInk, 21),
      iconBg: TOKENS.dangerBg,
      iconBorder: TOKENS.dangerBorder,
      title: "Attachment Scan Unavailable",
      subtitle: "Attachment Protection",
      whatHappenedHtml: `ShareSafe could not connect to the local security engine, so <strong>"${escapeHtml(file.name)}"</strong> could not be scanned for sensitive information before sending.`,
      guidanceText: "Cancel this attachment and start the ShareSafe local security service, or continue without scanning only if you trust the recipient and file contents.",
      detailsTitle: "Connection Details",
      detailsHtml: `
        <div style="margin-bottom: 4px;"><strong>Engine Endpoint:</strong> <code style="font-family:${MONO_STACK}; background:#FFFFFF; padding:2px 6px; border-radius:4px; border:1px solid ${TOKENS.border}; color:${TOKENS.inkPrimary};">http://127.0.0.1:5000</code></div>
        <div><strong>Diagnostic:</strong> ${escapeHtml(errMsg || "Local ShareSafe service is not running (run python app.py).")}</div>
      `,
      primaryLabel: "Cancel Attachment (Recommended)",
      primaryBg: TOKENS.inkPrimary,
      overrideLabel: "Send without scanning (Override)",
      onCancel,
      onOverride,
      cancelToastMessage: `Attachment cancelled. "${file.name}" was not sent.`,
      overrideToastMessage: `Override granted. Sending "${file.name}" without scanning.`
    });
  }

  function showUnsupportedModal(file, ext, onCancel, onOverride) {
    createNoticeModal({
      badgeText: "Unverified Format",
      badgeColors: { bg: TOKENS.warnBg, ink: TOKENS.warnInk, border: TOKENS.warnBorder },
      iconHtml: ICONS.shieldAlert(TOKENS.warnInk, 21),
      iconBg: TOKENS.warnBg,
      iconBorder: TOKENS.warnBorder,
      title: "Unsupported Attachment Format",
      subtitle: "Attachment Protection",
      whatHappenedHtml: `The file <strong>"${escapeHtml(file.name)}"</strong> uses the <code style="font-family:${MONO_STACK}; background:${TOKENS.bgMuted}; padding:2px 6px; border-radius:4px;">.${escapeHtml(ext || "unknown")}</code> format, which ShareSafe cannot inspect automatically.`,
      guidanceText: "Transmission has been paused to prevent accidental data leaks. Cancel the attachment or convert it to a supported format before sharing.",
      detailsTitle: "Supported Formats",
      detailsHtml: `
        <div><strong>Documents:</strong> PDF, DOCX, PPTX, XLSX, TXT, CSV</div>
        <div style="margin-top: 4px;"><strong>Images:</strong> PNG, JPG, JPEG, WEBP, BMP, TIFF, GIF</div>
      `,
      primaryLabel: "Cancel Attachment (Recommended)",
      primaryBg: TOKENS.inkPrimary,
      overrideLabel: "I understand the risk; send unverified file",
      onCancel,
      onOverride,
      cancelToastMessage: `Attachment cancelled. "${file.name}" was not sent.`,
      overrideToastMessage: `Override authorized. Sending unverified file.`
    });
  }

  /**
   * Consistent, spacious pre-send draft warning card used by both WhatsApp Web and Gmail adapters.
   */
  function showComposeThreatBanner({ id, mountFn, findingsCount, riskLevel }) {
    ensureStyles();
    const existing = document.getElementById(id);
    if (existing) existing.remove();

    const risk = String(riskLevel || "HIGH").toUpperCase();
    const isCritical = risk === "CRITICAL" || risk === "HIGH";
    const badgeBg = isCritical ? TOKENS.dangerBg : TOKENS.warnBg;
    const badgeInk = isCritical ? TOKENS.dangerInk : TOKENS.warnInk;
    const badgeBorder = isCritical ? TOKENS.dangerBorder : TOKENS.warnBorder;

    const banner = document.createElement("div");
    banner.id = id;
    banner.style.cssText = `
      background: ${TOKENS.bgCard};
      border: 1px solid ${TOKENS.border};
      border-left: 4px solid ${badgeInk};
      border-radius: 12px;
      padding: 14px 18px;
      box-shadow: ${TOKENS.shadowCard};
      font-family: ${FONT_STACK};
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      box-sizing: border-box;
      animation: ssUiSlideUp 0.2s ease;
    `;

    banner.innerHTML = `
      <div style="display: flex; align-items: flex-start; gap: 12px; min-width: 0;">
        <div style="width: 34px; height: 34px; border-radius: 9px; background: ${badgeBg}; border: 1px solid ${badgeBorder}; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
          ${ICONS.shieldAlert(badgeInk, 18)}
        </div>
        <div style="min-width: 0;">
          <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 3px;">
            <span style="font-size: 13px; font-weight: 700; color: ${TOKENS.inkPrimary};">
              ShareSafe Security Check
            </span>
            <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; padding: 2px 8px; border-radius: 999px; background: ${badgeBg}; color: ${badgeInk}; border: 1px solid ${badgeBorder};">
              ${escapeHtml(risk)} RISK
            </span>
          </div>
          <div style="font-size: 13px; color: ${TOKENS.inkSecondary}; line-height: 1.45;">
            Detected <strong>${findingsCount}</strong> sensitive item${findingsCount === 1 ? "" : "s"} in your draft. Open the ShareSafe extension to review and mask before sending.
          </div>
        </div>
      </div>
      <button type="button" class="ss-banner-dismiss" aria-label="Dismiss warning" style="
        background: none;
        border: none;
        padding: 6px;
        border-radius: 6px;
        cursor: pointer;
        color: ${TOKENS.inkMuted};
        flex-shrink: 0;
      ">
        ${ICONS.close(TOKENS.inkMuted, 16)}
      </button>
    `;

    banner.querySelector(".ss-banner-dismiss").addEventListener("click", () => {
      banner.remove();
    });

    mountFn(banner);
    return banner;
  }

  window.ShareSafeUI = {
    TOKENS,
    ICONS,
    FONT_STACK,
    MONO_STACK,
    escapeHtml,
    formatBytes,
    showScanningCard,
    showVerifiedCard,
    showToast,
    showOfflineModal,
    showUnsupportedModal,
    showComposeThreatBanner
  };
})();
