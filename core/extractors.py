import csv
import io
import os
import textwrap
from typing import Dict, Any, List, Tuple, Callable
from PIL import Image, ImageDraw, ImageFont


def _load_preview_font(size: int = 16, bold: bool = False):
    candidates = [
        r"C:\Windows\Fonts\consolab.ttf" if bold else r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                pass
    return ImageFont.load_default()


def render_text_preview_image(title: str, lines: List[str], out_path: str,
                              width: int = 1000, height: int = 1300) -> Tuple[int, int]:
    """Renders a clean visual PNG preview for text/office documents so the Workbench UI works uniformly."""
    img = Image.new("RGB", (width, height), (252, 252, 253))
    draw = ImageDraw.Draw(img)

    # Header bar
    draw.rectangle([0, 0, width, 64], fill=(15, 23, 42))
    header_font = _load_preview_font(18, bold=True)
    body_font = _load_preview_font(15, bold=False)

    safe_title = (title or "Document Preview")[:90]
    draw.text((28, 22), safe_title, fill=(248, 250, 252), font=header_font)

    y = 88
    line_height = 22
    max_chars = 96
    max_lines = (height - 110) // line_height
    rendered_lines = 0

    for raw_line in lines:
        if rendered_lines >= max_lines:
            draw.text((28, y), "... [Preview truncated — full content scanned] ...", fill=(100, 116, 139), font=body_font)
            break
        clean = str(raw_line).replace('\t', '    ')
        wrapped = textwrap.wrap(clean, width=max_chars) if clean.strip() else [""]
        for wline in wrapped:
            if rendered_lines >= max_lines:
                break
            draw.text((28, y), wline, fill=(30, 41, 59), font=body_font)
            y += line_height
            rendered_lines += 1

    img.save(out_path, format="PNG")
    return width, height


def _extract_office_core_properties(props) -> List[Dict[str, Any]]:
    """Extracts common core_properties from python-docx / python-pptx / openpyxl."""
    fields = [
        ('author', 'Author'),
        ('creator', 'Creator'),
        ('last_modified_by', 'Last Modified By'),
        ('lastModifiedBy', 'Last Modified By'),
        ('title', 'Title'),
        ('subject', 'Subject'),
        ('keywords', 'Keywords'),
        ('comments', 'Comments'),
        ('description', 'Description'),
        ('category', 'Category'),
        ('company', 'Company'),
    ]
    blocks = []
    seen = set()
    for attr, label in fields:
        if hasattr(props, attr):
            val = getattr(props, attr, None)
            if val is not None and str(val).strip():
                val_str = str(val).strip()
                key = (label, val_str)
                if key not in seen:
                    seen.add(key)
                    blocks.append({
                        'text': f"{label}: {val_str}",
                        'raw_value': val_str,
                        'field': attr,
                        'location': f"Metadata · {label}",
                        'source_type': 'metadata',
                    })
    return blocks


def extract_docx(file_path: str) -> Dict[str, Any]:
    """Extracts paragraphs, tables, headers/footers, hyperlinks, metadata, and embedded images from .docx."""
    import docx

    doc = docx.Document(file_path)
    blocks: List[Dict[str, Any]] = []
    preview_lines: List[str] = []

    # 1. Paragraphs
    for idx, para in enumerate(doc.paragraphs, start=1):
        txt = para.text.strip()
        if txt:
            blocks.append({
                'text': txt,
                'location': f"Paragraph {idx}",
                'source_type': 'paragraph',
            })
            preview_lines.append(txt)

    # 2. Tables
    for t_idx, table in enumerate(doc.tables, start=1):
        for r_idx, row in enumerate(table.rows, start=1):
            row_vals = []
            for c_idx, cell in enumerate(row.cells, start=1):
                ctext = cell.text.strip()
                if ctext:
                    blocks.append({
                        'text': ctext,
                        'location': f"Table {t_idx} · Row {r_idx}, Col {c_idx}",
                        'source_type': 'table_cell',
                    })
                    row_vals.append(ctext)
            if row_vals:
                preview_lines.append(" | ".join(row_vals))

    # 3. Headers & Footers
    for s_idx, section in enumerate(doc.sections, start=1):
        for kind, hf in [('Header', section.header), ('Footer', section.footer)]:
            if hf is None:
                continue
            for p_idx, para in enumerate(hf.paragraphs, start=1):
                txt = para.text.strip()
                if txt:
                    blocks.append({
                        'text': txt,
                        'location': f"Section {s_idx} {kind} · P{p_idx}",
                        'source_type': kind.lower(),
                    })
                    preview_lines.append(f"[{kind}] {txt}")

    # 4. External Hyperlinks
    try:
        for rel in doc.part.rels.values():
            if "hyperlink" in rel.reltype and rel.target_ref:
                blocks.append({
                    'text': rel.target_ref,
                    'location': "Hyperlink Target",
                    'source_type': 'hyperlink',
                })
    except Exception:
        pass

    # 5. Embedded Images (limit to 15 images, max 10 MB each)
    images: List[Dict[str, Any]] = []
    try:
        img_idx = 0
        for part in doc.part.related_parts.values():
            ct = getattr(part, 'content_type', '') or ''
            if ct.startswith('image/'):
                blob = getattr(part, 'blob', b'')
                if blob and len(blob) <= 10 * 1024 * 1024:
                    img_idx += 1
                    images.append({
                        'bytes': blob,
                        'location': f"Embedded Image {img_idx}",
                    })
                    if img_idx >= 15:
                        break
    except Exception:
        pass

    # 6. Core Properties Metadata
    metadata_blocks = _extract_office_core_properties(doc.core_properties)

    if not preview_lines:
        preview_lines = ["(Empty DOCX document or contains only embedded media)"]

    return {
        'format_category': 'docx',
        'pages': [{
            'page_number': 1,
            'title': f"DOCX Document — {os.path.basename(file_path)}",
            'blocks': blocks,
            'images': images,
            'preview_lines': preview_lines,
        }],
        'metadata_blocks': metadata_blocks,
    }


def extract_pptx(file_path: str) -> Dict[str, Any]:
    """Extracts slide text, tables, speaker notes, hyperlinks, metadata, and embedded pictures from .pptx."""
    import pptx
    from pptx.enum.shapes import MSO_SHAPE_TYPE

    prs = pptx.Presentation(file_path)
    pages: List[Dict[str, Any]] = []

    for s_idx, slide in enumerate(prs.slides, start=1):
        blocks: List[Dict[str, Any]] = []
        images: List[Dict[str, Any]] = []
        preview_lines: List[str] = [f"--- Slide {s_idx} ---"]

        for sh_idx, shape in enumerate(slide.shapes, start=1):
            if shape.has_text_frame:
                txt = shape.text_frame.text.strip()
                if txt:
                    blocks.append({
                        'text': txt,
                        'location': f"Slide {s_idx} · Shape {sh_idx}",
                        'source_type': 'slide_text',
                    })
                    preview_lines.extend(txt.splitlines())

                # Run-level hyperlinks
                for para in shape.text_frame.paragraphs:
                    for run in para.runs:
                        try:
                            addr = run.hyperlink.address if run.hyperlink else None
                            if addr:
                                blocks.append({
                                    'text': addr,
                                    'location': f"Slide {s_idx} · Hyperlink",
                                    'source_type': 'hyperlink',
                                })
                        except Exception:
                            pass

            if shape.has_table:
                for r_idx, row in enumerate(shape.table.rows, start=1):
                    row_vals = []
                    for c_idx, cell in enumerate(row.cells, start=1):
                        ctext = cell.text.strip()
                        if ctext:
                            blocks.append({
                                'text': ctext,
                                'location': f"Slide {s_idx} · Table R{r_idx}C{c_idx}",
                                'source_type': 'table_cell',
                            })
                            row_vals.append(ctext)
                    if row_vals:
                        preview_lines.append(" | ".join(row_vals))

            try:
                if shape.shape_type == MSO_SHAPE_TYPE.PICTURE and len(images) < 10:
                    blob = shape.image.blob
                    if blob and len(blob) <= 10 * 1024 * 1024:
                        images.append({
                            'bytes': blob,
                            'location': f"Slide {s_idx} · Picture {len(images) + 1}",
                        })
            except Exception:
                pass

        # Speaker notes
        try:
            if slide.has_notes_slide and slide.notes_slide.notes_text_frame:
                notes = slide.notes_slide.notes_text_frame.text.strip()
                if notes:
                    blocks.append({
                        'text': notes,
                        'location': f"Slide {s_idx} · Speaker Notes",
                        'source_type': 'speaker_notes',
                    })
                    preview_lines.append("")
                    preview_lines.append(f"[Speaker Notes] {notes}")
        except Exception:
            pass

        if len(preview_lines) == 1:
            preview_lines.append("(No text content on this slide)")

        pages.append({
            'page_number': s_idx,
            'title': f"PPTX Slide {s_idx} — {os.path.basename(file_path)}",
            'blocks': blocks,
            'images': images,
            'preview_lines': preview_lines,
        })

    if not pages:
        pages.append({
            'page_number': 1,
            'title': f"PPTX Presentation — {os.path.basename(file_path)}",
            'blocks': [],
            'images': [],
            'preview_lines': ["(Presentation contains 0 slides)"],
        })

    metadata_blocks = _extract_office_core_properties(prs.core_properties)

    return {
        'format_category': 'pptx',
        'pages': pages,
        'metadata_blocks': metadata_blocks,
    }


def extract_xlsx(file_path: str) -> Dict[str, Any]:
    """Extracts sheet-by-sheet cell values, comments, hyperlinks, and workbook metadata from .xlsx."""
    import openpyxl

    wb = openpyxl.load_workbook(file_path, data_only=False)
    pages: List[Dict[str, Any]] = []

    try:
        for sh_idx, sheet_name in enumerate(wb.sheetnames, start=1):
            ws = wb[sheet_name]
            blocks: List[Dict[str, Any]] = []
            preview_lines: List[str] = [f"=== Sheet: {sheet_name} ==="]

            for r_idx, row in enumerate(ws.iter_rows(values_only=False), start=1):
                row_display = []
                for cell in row:
                    val = cell.value
                    if val is not None and str(val).strip():
                        val_str = str(val).strip()
                        blocks.append({
                            'text': val_str,
                            'location': f"Sheet '{sheet_name}' · {cell.coordinate}",
                            'source_type': 'cell',
                        })
                        row_display.append(val_str)

                    if cell.hyperlink and cell.hyperlink.target:
                        blocks.append({
                            'text': cell.hyperlink.target,
                            'location': f"Sheet '{sheet_name}' · {cell.coordinate} Hyperlink",
                            'source_type': 'hyperlink',
                        })

                    if cell.comment and cell.comment.text:
                        blocks.append({
                            'text': cell.comment.text.strip(),
                            'location': f"Sheet '{sheet_name}' · {cell.coordinate} Comment",
                            'source_type': 'comment',
                        })
                        preview_lines.append(f"[Comment {cell.coordinate}] {cell.comment.text.strip()}")

                if row_display:
                    preview_lines.append(" | ".join(row_display))

            if len(preview_lines) == 1:
                preview_lines.append("(Empty worksheet)")

            pages.append({
                'page_number': sh_idx,
                'title': f"XLSX Sheet '{sheet_name}' — {os.path.basename(file_path)}",
                'blocks': blocks,
                'images': [],
                'preview_lines': preview_lines,
            })

        metadata_blocks = _extract_office_core_properties(wb.properties)
    finally:
        wb.close()

    if not pages:
        pages.append({
            'page_number': 1,
            'title': f"XLSX Workbook — {os.path.basename(file_path)}",
            'blocks': [],
            'images': [],
            'preview_lines': ["(Empty workbook)"],
        })

    return {
        'format_category': 'xlsx',
        'pages': pages,
        'metadata_blocks': metadata_blocks,
    }


def _decode_text_file(file_path: str) -> str:
    with open(file_path, 'rb') as f:
        raw = f.read()
    try:
        return raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        return raw.decode('latin-1')


def extract_text(file_path: str) -> Dict[str, Any]:
    """Extracts lines from a .txt file into Common Content Representation."""
    content = _decode_text_file(file_path)
    lines = content.splitlines()
    blocks: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines, start=1):
        if line.strip():
            blocks.append({
                'text': line,
                'location': f"Line {idx}",
                'source_type': 'text_line',
            })

    preview_lines = lines if lines else ["(Empty text file)"]
    return {
        'format_category': 'text',
        'pages': [{
            'page_number': 1,
            'title': f"TXT Document — {os.path.basename(file_path)}",
            'blocks': blocks,
            'images': [],
            'preview_lines': preview_lines,
        }],
        'metadata_blocks': [],
    }


def extract_csv(file_path: str) -> Dict[str, Any]:
    """Extracts rows and cells from a .csv file into Common Content Representation."""
    content = _decode_text_file(file_path)
    reader = csv.reader(io.StringIO(content))
    blocks: List[Dict[str, Any]] = []
    preview_lines: List[str] = []

    for r_idx, row in enumerate(reader, start=1):
        row_text = " | ".join(cell for cell in row if cell.strip())
        if row_text:
            blocks.append({
                'text': " ".join(cell.strip() for cell in row if cell.strip()),
                'location': f"CSV Row {r_idx}",
                'source_type': 'csv_row',
            })
            preview_lines.append(row_text)

    if not preview_lines:
        preview_lines = ["(Empty CSV file)"]

    return {
        'format_category': 'csv',
        'pages': [{
            'page_number': 1,
            'title': f"CSV Data — {os.path.basename(file_path)}",
            'blocks': blocks,
            'images': [],
            'preview_lines': preview_lines,
        }],
        'metadata_blocks': [],
    }


EXTRACTOR_MAP: Dict[str, Callable[[str], Dict[str, Any]]] = {
    'docx': extract_docx,
    'pptx': extract_pptx,
    'xlsx': extract_xlsx,
    'text': extract_text,
    'csv': extract_csv,
}


def extract_document(file_path: str, format_category: str) -> Dict[str, Any]:
    """Dispatches to the appropriate format extractor and returns Common Content Representation."""
    extractor = EXTRACTOR_MAP.get(format_category)
    if not extractor:
        raise ValueError(f"No extractor registered for format category '{format_category}'.")
    return extractor(file_path)
