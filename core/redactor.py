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
                # Pure solid white
                cv2.rectangle(result, (x1, y1), (x2, y2), (255, 255, 255), -1)

            elif style == 'blur':
                # Gaussian blur with heavy sigma
                roi = result[y1:y2, x1:x2]
                # Ensure kernel size is odd and proportional to height
                ksize = max(15, (min(rw, rh) // 2) * 2 + 1)
                ksize = min(ksize, 51)
                blurred_roi = cv2.GaussianBlur(roi, (ksize, ksize), 30)
                result[y1:y2, x1:x2] = blurred_roi

            elif style == 'pixelate':
                # Mosaic pixelation
                roi = result[y1:y2, x1:x2]
                pixel_size = max(6, min(rw, rh) // 6)
                small_w = max(1, rw // pixel_size)
                small_h = max(1, rh // pixel_size)
                small_roi = cv2.resize(roi, (small_w, small_h), interpolation=cv2.INTER_LINEAR)
                pixelated_roi = cv2.resize(small_roi, (rw, rh), interpolation=cv2.INTER_NEAREST)
                result[y1:y2, x1:x2] = pixelated_roi

            elif style == 'stamp':
                # Dark obsidian block with stylized warning text badge
                cv2.rectangle(result, (x1, y1), (x2, y2), (18, 18, 24), -1)
                cv2.rectangle(result, (x1, y1), (x2, y2), (220, 38, 38), 1)  # Red border

                badge_text = f"[{label[:14]}]" if label else "[REDACTED]"
                font = cv2.FONT_HERSHEY_SIMPLEX
                font_scale = min(0.6, max(0.25, (rh / 40.0)))
                thickness = 1
                text_size = cv2.getTextSize(badge_text, font, font_scale, thickness)[0]

                text_x = x1 + max(2, (rw - text_size[0]) // 2)
                text_y = y1 + max(text_size[1] + 2, (rh + text_size[1]) // 2)

                if rw > 30 and rh > 14:
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

            # 1. Native PyMuPDF content stream redactions (physically removes text objects from PDF stream)
            for r in page_redacts:
                bbox = r.get('bbox')
                if bbox and len(bbox) == 4:
                    # Convert from preview pixel coords back to PDF points
                    x, y, w, h = bbox
                    pdf_rect = pymupdf.Rect(x / zoom, y / zoom, (x + w) / zoom, (y + h) / zoom)
                    page.add_redact_annot(pdf_rect, fill=(0, 0, 0))

            page.apply_redactions()

            # 2. To support all custom redaction styles (blur, pixelate, stamp) and prevent font dictionary recovery,
            # render page pixmap and apply custom styling
            pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
            # Convert pixmap to numpy BGR image
            img_bytes = pix.tobytes("png")
            nparr = np.frombuffer(img_bytes, np.uint8)
            img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            # Apply stylized effects
            redacted_np = cls.redact_image_np(img_np, page_redacts)

            # Encode back to clean image
            _, encoded_png = cv2.imencode(".png", redacted_np)
            
            # Create a brand new clean flattened PDF page
            # Page dimensions in points
            rect = page.rect
            new_page = out_doc.new_page(width=rect.width, height=rect.height)
            new_page.insert_image(rect, stream=encoded_png.tobytes())

        # Strip all metadata from output PDF
        out_doc.set_metadata({})
        out_doc.save(output_path, garbage=4, deflate=True)
        out_doc.close()
        doc.close()

        return output_path
