import os
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import pymupdf
from typing import List, Dict, Any, Optional

class DocumentRedactor:
    """Applies irreversible redactions to Images and PDFs with multiple styling modes and true PDF content stream sanitization."""

    @classmethod
    def redact_image_np(cls, img_np: np.ndarray, boxes_with_styles: List[Dict[str, Any]]) -> np.ndarray:
        """Applies redactions directly to an image numpy array (BGR)."""
        result = img_np.copy()
        img_h, img_w = result.shape[:2]

        for item in boxes_with_styles:
            bbox = item.get('bbox')
            if not bbox or len(bbox) != 4:
                continue

            x, y, w, h = [int(round(v)) for v in bbox]
            # Clip bounds to image dimensions
            x1 = max(0, min(x, img_w - 1))
            y1 = max(0, min(y, img_h - 1))
            x2 = max(x1 + 1, min(x + w, img_w))
            y2 = max(y1 + 1, min(y + h, img_h))

            rw = x2 - x1
            rh = y2 - y1
            if rw <= 0 or rh <= 0:
                continue

            style = item.get('style', 'blackout').lower()
            label = item.get('label', 'REDACTED').upper()

            if style == 'blackout':
                # Pure solid black
                cv2.rectangle(result, (x1, y1), (x2, y2), (0, 0, 0), -1)

            elif style == 'whiteout':
                # Pure solid white with clean subtle boundary
                cv2.rectangle(result, (x1, y1), (x2, y2), (255, 255, 255), -1)
                cv2.rectangle(result, (x1, y1), (x2, y2), (220, 220, 225), 1)

            elif style == 'blur':
                # Gaussian blur with heavy multi-pass for complete privacy
                roi = result[y1:y2, x1:x2]
                max_k = min(rw, rh)
                if max_k % 2 == 0:
                    max_k -= 1
                ksize = max(3, min(max_k, 31))
                if ksize >= 3:
                    blurred_roi = cv2.GaussianBlur(roi, (ksize, ksize), 15)
                    blurred_roi = cv2.GaussianBlur(blurred_roi, (ksize, ksize), 15)
                    result[y1:y2, x1:x2] = blurred_roi
                else:
                    cv2.rectangle(result, (x1, y1), (x2, y2), (180, 180, 180), -1)

            elif style == 'pixelate':
                # Mosaic pixelation
                roi = result[y1:y2, x1:x2]
                pixel_size = max(4, min(rw, rh) // 4)
                small_w = max(1, rw // pixel_size)
                small_h = max(1, rh // pixel_size)
                small_roi = cv2.resize(roi, (small_w, small_h), interpolation=cv2.INTER_LINEAR)
                pixelated_roi = cv2.resize(small_roi, (rw, rh), interpolation=cv2.INTER_NEAREST)
                result[y1:y2, x1:x2] = pixelated_roi

            elif style == 'stamp':
                # Dark obsidian block with stylized warning text badge
                cv2.rectangle(result, (x1, y1), (x2, y2), (18, 18, 24), -1)
                cv2.rectangle(result, (x1, y1), (x2, y2), (220, 38, 38), 1)  # Red border

                badge_text = f"[{label[:12]}]" if label and label != 'REDACTED' else "[REDACTED]"
                font = cv2.FONT_HERSHEY_SIMPLEX
                font_scale = min(0.5, max(0.2, (rh / 45.0)))
                thickness = 1
                text_size = cv2.getTextSize(badge_text, font, font_scale, thickness)[0]

                text_x = x1 + max(2, (rw - text_size[0]) // 2)
                text_y = y1 + max(text_size[1] + 2, (rh + text_size[1]) // 2)

                if rw > 35 and rh > 12:
                    cv2.putText(result, badge_text, (text_x, text_y), font, font_scale, (255, 255, 255), thickness, cv2.LINE_AA)

            else:
                # Default to blackout
                cv2.rectangle(result, (x1, y1), (x2, y2), (0, 0, 0), -1)

        return result

    @classmethod
    def redact_document(cls, 
                        original_file_path: str, 
                        is_pdf: bool, 
                        session_dir: str, 
                        redactions: List[Dict[str, Any]], 
                        output_filename: str) -> str:
        """Executes full permanent redaction on document and produces a sanitized, flattened output file."""
        output_path = os.path.join(session_dir, output_filename)

        if is_pdf:
            return cls._redact_pdf_permanent(original_file_path, session_dir, redactions, output_path)
        else:
            return cls._redact_image_permanent(original_file_path, redactions, output_path)

    @classmethod
    def _redact_image_permanent(cls, img_path: str, redactions: List[Dict[str, Any]], output_path: str) -> str:
        """Redacts image file and strips all metadata."""
        img_np = cv2.imread(img_path)
        if img_np is None:
            raise ValueError("Could not read original image.")

        # Filter redactions for page 1
        page1_redactions = [r for r in redactions if r.get('page', 1) == 1]
        redacted_np = cls.redact_image_np(img_np, page1_redactions)

        # Save to output path without any EXIF
        cv2.imwrite(output_path, redacted_np)
        return output_path

    @classmethod
    def _redact_pdf_permanent(cls, 
                              pdf_path: str, 
                              session_dir: str, 
                              redactions: List[Dict[str, Any]], 
                              output_path: str) -> str:
        """Applies true redaction and high-fidelity rasterization flattening to destroy underlying text layers."""
        doc = pymupdf.open(pdf_path)
        out_doc = pymupdf.open()  # Clean output document

        # PyMuPDF zoom factor used during scan preview rendering
        zoom = 150 / 72

        for page_idx in range(len(doc)):
            page = doc[page_idx]
            page_num = page_idx + 1

            # Find all redactions for this page
            page_redacts = [r for r in redactions if r.get('page') == page_num]

            # 1. Render original page to high-DPI pixmap before altering
            pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))

            # Convert pixmap to numpy BGR image
            img_bytes = pix.tobytes("png")
            nparr = np.frombuffer(img_bytes, np.uint8)
            img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            # 2. Apply stylized effects (blur, pixelate, whiteout, blackout, stamp) directly to image pixels
            redacted_np = cls.redact_image_np(img_np, page_redacts)

            # 3. Encode back to clean image
            _, encoded_png = cv2.imencode(".png", redacted_np)
            
            # 4. Create a brand new clean flattened PDF page with NO text objects or font tables
            rect = page.rect
            new_page = out_doc.new_page(width=rect.width, height=rect.height)
            new_page.insert_image(rect, stream=encoded_png.tobytes())

        # Strip all metadata from output PDF
        out_doc.set_metadata({})
        out_doc.save(output_path, garbage=4, deflate=True)
        out_doc.close()
        doc.close()

        return output_path
