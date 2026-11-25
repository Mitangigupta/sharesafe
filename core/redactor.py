import csv
import io
import os
from typing import List, Dict, Any, Tuple, Optional

try:
    import cv2
    import numpy as np
    _CV2_AVAILABLE = True
except ImportError:
    cv2 = None
    np = None
    _CV2_AVAILABLE = False

import pymupdf
from PIL import Image, ImageOps

from core.format_registry import get_format_category
from core.metadata_cleaner import MetadataCleaner


class DocumentRedactor:
    """Applies irreversible redactions across PDFs, Images, DOCX, PPTX, XLSX, TXT, and CSV."""

    @classmethod
    def redact_image_np(cls, img_np: "np.ndarray", boxes_with_styles: List[Dict[str, Any]]) -> "np.ndarray":
        """Applies redactions directly to an image numpy array (BGR)."""
        result = img_np.copy()
        img_h, img_w = result.shape[:2]

        for item in boxes_with_styles:
            bbox = item.get('bbox')
            if not bbox or len(bbox) != 4:
                continue

            x, y, w, h = [int(round(v)) for v in bbox]
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
                cv2.rectangle(result, (x1, y1), (x2, y2), (0, 0, 0), -1)

            elif style == 'whiteout':
                cv2.rectangle(result, (x1, y1), (x2, y2), (255, 255, 255), -1)
                cv2.rectangle(result, (x1, y1), (x2, y2), (220, 220, 225), 1)

            elif style == 'blur':
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
                roi = result[y1:y2, x1:x2]
                pixel_size = max(4, min(rw, rh) // 4)
                small_w = max(1, rw // pixel_size)
                small_h = max(1, rh // pixel_size)
                small_roi = cv2.resize(roi, (small_w, small_h), interpolation=cv2.INTER_LINEAR)
                pixelated_roi = cv2.resize(small_roi, (rw, rh), interpolation=cv2.INTER_NEAREST)
                result[y1:y2, x1:x2] = pixelated_roi

            elif style == 'stamp':
                cv2.rectangle(result, (x1, y1), (x2, y2), (18, 18, 24), -1)
                cv2.rectangle(result, (x1, y1), (x2, y2), (220, 38, 38), 1)

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
                cv2.rectangle(result, (x1, y1), (x2, y2), (0, 0, 0), -1)

        return result

    @classmethod
    def redact_document(cls,
                        original_file_path: str,
                        is_pdf: bool,
                        session_dir: str,
                        redactions: List[Dict[str, Any]],
                        output_filename: str,
                        format_category: Optional[str] = None) -> str:
        """Executes format-specific permanent redaction and produces a sanitized output file."""
        output_path = os.path.join(session_dir, output_filename)
        category = format_category or ('pdf' if is_pdf else get_format_category(original_file_path))

        if category == 'pdf':
            return cls._redact_pdf_permanent(original_file_path, session_dir, redactions, output_path)
        elif category == 'image':
            return cls._redact_image_permanent(original_file_path, redactions, output_path)
        elif category == 'docx':
            return cls._redact_docx(original_file_path, redactions, output_path)
        elif category == 'pptx':
            return cls._redact_pptx(original_file_path, redactions, output_path)
        elif category == 'xlsx':
            return cls._redact_xlsx(original_file_path, redactions, output_path)
        elif category in ('text', 'csv'):
            return cls._redact_text_or_csv(original_file_path, redactions, output_path, is_csv=(category == 'csv'))
        else:
            raise ValueError(f"Unsupported format category for redaction: '{category}'.")

    @classmethod
    def _redact_image_permanent(cls, img_path: str, redactions: List[Dict[str, Any]], output_path: str) -> str:
        """Redacts image file (PNG/JPG/WEBP/BMP/TIFF/GIF) and strips all metadata."""
        with Image.open(img_path) as raw_img:
            if getattr(raw_img, 'n_frames', 1) > 1:
                raw_img.seek(0)
            pil_img = ImageOps.exif_transpose(raw_img)
            if pil_img is None:
                pil_img = raw_img.copy()
            if pil_img.mode in ('RGBA', 'LA', 'P'):
                bg = Image.new('RGB', pil_img.size, (255, 255, 255))
                if pil_img.mode == 'RGBA':
                    bg.paste(pil_img, mask=pil_img.split()[3])
                else:
                    bg.paste(pil_img.convert('RGB'))
                pil_img = bg
            elif pil_img.mode != 'RGB':
                pil_img = pil_img.convert('RGB')

        if _CV2_AVAILABLE:
            img_np = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
            page1_redactions = [r for r in redactions if r.get('page', 1) == 1]
            redacted_np = cls.redact_image_np(img_np, page1_redactions)
            out_pil = Image.fromarray(cv2.cvtColor(redacted_np, cv2.COLOR_BGR2RGB))
        else:
            out_pil = pil_img

        # Saving via PIL without exif= strips all EXIF/GPS/XMP metadata and supports GIF/TIFF/WEBP/BMP/PNG/JPEG
        out_ext = os.path.splitext(output_path)[1].lower().lstrip('.')
        save_fmt = {
            'jpg': 'JPEG',
            'jpeg': 'JPEG',
            'png': 'PNG',
            'webp': 'WEBP',
            'bmp': 'BMP',
            'tiff': 'TIFF',
            'tif': 'TIFF',
            'gif': 'GIF',
        }.get(out_ext)

        if save_fmt == 'GIF':
            out_pil.convert('P', palette=Image.Palette.ADAPTIVE).save(output_path, format='GIF')
        elif save_fmt:
            out_pil.save(output_path, format=save_fmt)
        else:
            out_pil.save(output_path)

        return output_path

    @classmethod
    def _redact_pdf_permanent(cls,
                              pdf_path: str,
                              session_dir: str,
                              redactions: List[Dict[str, Any]],
                              output_path: str) -> str:
        """Applies true redaction and high-fidelity rasterization flattening to destroy underlying text layers."""
        doc = pymupdf.open(pdf_path)
        out_doc = pymupdf.open()

        zoom = 150 / 72

        for page_idx in range(len(doc)):
            page = doc[page_idx]
            page_num = page_idx + 1
            page_redacts = [r for r in redactions if r.get('page') == page_num]

            pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
            img_bytes = pix.tobytes("png")
            nparr = np.frombuffer(img_bytes, np.uint8)
            img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            redacted_np = cls.redact_image_np(img_np, page_redacts)
            _, encoded_png = cv2.imencode(".png", redacted_np)

            rect = page.rect
            new_page = out_doc.new_page(width=rect.width, height=rect.height)
            new_page.insert_image(rect, stream=encoded_png.tobytes())

        out_doc.set_metadata({})
        out_doc.save(output_path, garbage=4, deflate=True)
        out_doc.close()
        doc.close()

        return output_path

    @staticmethod
    def _build_replacement_pairs(redactions: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
        """Builds deduplicated (target_value, replacement_text) pairs sorted longest-first."""
        pairs: Dict[str, str] = {}
        for r in redactions:
            val = r.get('value')
            if not val or not isinstance(val, str):
                continue
            val_clean = val.strip()
            if not val_clean or val_clean in ('[face detected]', '[QR]'):
                continue
            masked = r.get('masked')
            if masked and isinstance(masked, str) and masked.strip() and masked.strip() != val_clean:
                repl = masked.strip()
            else:
                label = str(r.get('label', 'REDACTED')).upper().replace(' ', '_')[:16]
                repl = f"[REDACTED:{label}]"
            pairs[val_clean] = repl
            if val != val_clean:
                pairs[val] = repl

        return sorted(pairs.items(), key=lambda kv: len(kv[0]), reverse=True)

    @staticmethod
    def _replace_in_text(text: str, pairs: List[Tuple[str, str]]) -> str:
        if not text or not pairs:
            return text
        updated = text
        for target, repl in pairs:
            if target in updated:
                updated = updated.replace(target, repl)
        return updated

    @classmethod
    def _replace_in_paragraph(cls, paragraph, pairs: List[Tuple[str, str]]) -> None:
        """Replaces sensitive tokens in a python-docx or python-pptx paragraph while preserving run styles."""
        if not pairs or not paragraph.text:
            return
        full_text = paragraph.text
        if not any(target in full_text for target, _ in pairs):
            return

        # 1. Try per-run replacement first (preserves exact per-run formatting)
        for run in paragraph.runs:
            if run.text:
                new_run_text = cls._replace_in_text(run.text, pairs)
                if new_run_text != run.text:
                    run.text = new_run_text

        # 2. If a sensitive token spanned multiple runs, replace on full paragraph text
        after_runs = paragraph.text
        if any(target in after_runs for target, _ in pairs):
            replaced = cls._replace_in_text(after_runs, pairs)
            if paragraph.runs:
                paragraph.runs[0].text = replaced
                for run in paragraph.runs[1:]:
                    run.text = ""
            else:
                paragraph.text = replaced

    @classmethod
    def _redact_docx(cls, docx_path: str, redactions: List[Dict[str, Any]], output_path: str) -> str:
        """Sanitizes .docx paragraphs, tables, headers/footers, hyperlinks, and scrubs core properties."""
        import docx

        doc = docx.Document(docx_path)
        pairs = cls._build_replacement_pairs(redactions)

        for para in doc.paragraphs:
            cls._replace_in_paragraph(para, pairs)

        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for para in cell.paragraphs:
                        cls._replace_in_paragraph(para, pairs)

        for section in doc.sections:
            for hf in (section.header, section.footer):
                if hf is None:
                    continue
                for para in hf.paragraphs:
                    cls._replace_in_paragraph(para, pairs)
                for table in hf.tables:
                    for row in table.rows:
                        for cell in row.cells:
                            for para in cell.paragraphs:
                                cls._replace_in_paragraph(para, pairs)

        # Sanitize external hyperlink targets if they match any redacted value
        try:
            for rel in doc.part.rels.values():
                if "hyperlink" in rel.reltype and rel.target_ref:
                    new_ref = cls._replace_in_text(rel.target_ref, pairs)
                    if new_ref != rel.target_ref:
                        rel._target = "https://redacted.invalid"
        except Exception:
            pass

        MetadataCleaner.scrub_office_properties(doc.core_properties)
        doc.save(output_path)
        return output_path

    @classmethod
    def _redact_pptx(cls, pptx_path: str, redactions: List[Dict[str, Any]], output_path: str) -> str:
        """Sanitizes .pptx slide text, tables, speaker notes, hyperlinks, and scrubs core properties."""
        import pptx

        prs = pptx.Presentation(pptx_path)
        pairs = cls._build_replacement_pairs(redactions)

        for slide in prs.slides:
            for shape in slide.shapes:
                if shape.has_text_frame:
                    for para in shape.text_frame.paragraphs:
                        cls._replace_in_paragraph(para, pairs)
                        for run in para.runs:
                            try:
                                if run.hyperlink and run.hyperlink.address:
                                    new_addr = cls._replace_in_text(run.hyperlink.address, pairs)
                                    if new_addr != run.hyperlink.address:
                                        run.hyperlink.address = "https://redacted.invalid"
                            except Exception:
                                pass

                if shape.has_table:
                    for row in shape.table.rows:
                        for cell in row.cells:
                            for para in cell.text_frame.paragraphs:
                                cls._replace_in_paragraph(para, pairs)

            try:
                if slide.has_notes_slide and slide.notes_slide.notes_text_frame:
                    for para in slide.notes_slide.notes_text_frame.paragraphs:
                        cls._replace_in_paragraph(para, pairs)
            except Exception:
                pass

        MetadataCleaner.scrub_office_properties(prs.core_properties)
        prs.save(output_path)
        return output_path

    @classmethod
    def _redact_xlsx(cls, xlsx_path: str, redactions: List[Dict[str, Any]], output_path: str) -> str:
        """Sanitizes .xlsx cells, comments, hyperlinks, and scrubs workbook properties."""
        import openpyxl

        wb = openpyxl.load_workbook(xlsx_path)
        pairs = cls._build_replacement_pairs(redactions)

        try:
            for ws in wb.worksheets:
                for row in ws.iter_rows():
                    for cell in row:
                        if cell.value is not None:
                            val_str = str(cell.value)
                            new_val = cls._replace_in_text(val_str, pairs)
                            if new_val != val_str:
                                cell.value = new_val

                        if cell.hyperlink and cell.hyperlink.target:
                            new_target = cls._replace_in_text(cell.hyperlink.target, pairs)
                            if new_target != cell.hyperlink.target:
                                cell.hyperlink = None

                        if cell.comment and cell.comment.text:
                            new_comment = cls._replace_in_text(cell.comment.text, pairs)
                            if new_comment != cell.comment.text:
                                cell.comment.text = new_comment

            MetadataCleaner.scrub_office_properties(wb.properties)
            wb.save(output_path)
        finally:
            wb.close()

        return output_path

    @classmethod
    def _redact_text_or_csv(cls, file_path: str, redactions: List[Dict[str, Any]], output_path: str, is_csv: bool = False) -> str:
        """Sanitizes .txt or .csv files while preserving line/CSV structure."""
        with open(file_path, 'rb') as f:
            raw = f.read()
        try:
            content = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            content = raw.decode('latin-1')

        pairs = cls._build_replacement_pairs(redactions)

        if is_csv:
            reader = csv.reader(io.StringIO(content))
            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator='\n')
            for row in reader:
                writer.writerow([cls._replace_in_text(cell, pairs) for cell in row])
            sanitized_text = buf.getvalue()
        else:
            sanitized_text = cls._replace_in_text(content, pairs)

        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            f.write(sanitized_text)

        return output_path
