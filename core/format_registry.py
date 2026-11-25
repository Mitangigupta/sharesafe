import os
import zipfile
from typing import Dict, Tuple, Set
import pymupdf
from PIL import Image

# Guard against decompression bombs on untrusted images
Image.MAX_IMAGE_PIXELS = 50_000_000  # ~50 megapixels max

MAX_OFFICE_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB zip-bomb limit
MAX_PDF_PAGES = 50
MAX_TEXT_BYTES = 20 * 1024 * 1024  # 20 MB max for raw text/csv

FORMAT_REGISTRY: Dict[str, Dict[str, str]] = {
    'pdf': {
        'category': 'pdf',
        'mime_type': 'application/pdf',
        'label': 'PDF Document',
    },
    'png': {
        'category': 'image',
        'mime_type': 'image/png',
        'label': 'PNG Image',
    },
    'jpg': {
        'category': 'image',
        'mime_type': 'image/jpeg',
        'label': 'JPEG Image',
    },
    'jpeg': {
        'category': 'image',
        'mime_type': 'image/jpeg',
        'label': 'JPEG Image',
    },
    'webp': {
        'category': 'image',
        'mime_type': 'image/webp',
        'label': 'WEBP Image',
    },
    'bmp': {
        'category': 'image',
        'mime_type': 'image/bmp',
        'label': 'BMP Image',
    },
    'tiff': {
        'category': 'image',
        'mime_type': 'image/tiff',
        'label': 'TIFF Image',
    },
    'tif': {
        'category': 'image',
        'mime_type': 'image/tiff',
        'label': 'TIFF Image',
    },
    'gif': {
        'category': 'image',
        'mime_type': 'image/gif',
        'label': 'GIF Image',
    },
    'docx': {
        'category': 'docx',
        'mime_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'label': 'Word Document',
    },
    'pptx': {
        'category': 'pptx',
        'mime_type': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'label': 'PowerPoint Presentation',
    },
    'xlsx': {
        'category': 'xlsx',
        'mime_type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'label': 'Excel Spreadsheet',
    },
    'txt': {
        'category': 'text',
        'mime_type': 'text/plain',
        'label': 'Plain Text',
    },
    'csv': {
        'category': 'csv',
        'mime_type': 'text/csv',
        'label': 'CSV Spreadsheet',
    },
}


def get_allowed_extensions() -> Set[str]:
    return set(FORMAT_REGISTRY.keys())


def get_extension(filename_or_path: str) -> str:
    if not filename_or_path or '.' not in filename_or_path:
        return ''
    return os.path.splitext(filename_or_path)[1].lower().lstrip('.')


def is_supported_extension(ext: str) -> bool:
    return (ext or '').lower().lstrip('.') in FORMAT_REGISTRY


def get_format_category(ext_or_path: str) -> str:
    ext = ext_or_path.lower().lstrip('.') if '.' not in ext_or_path else get_extension(ext_or_path)
    info = FORMAT_REGISTRY.get(ext)
    return info['category'] if info else 'unknown'


def get_mime_type(ext_or_path: str) -> str:
    ext = ext_or_path.lower().lstrip('.') if '.' not in ext_or_path else get_extension(ext_or_path)
    info = FORMAT_REGISTRY.get(ext)
    return info['mime_type'] if info else 'application/octet-stream'


def get_format_label(ext_or_path: str) -> str:
    ext = ext_or_path.lower().lstrip('.') if '.' not in ext_or_path else get_extension(ext_or_path)
    info = FORMAT_REGISTRY.get(ext)
    return info['label'] if info else 'Document'


def validate_file_content(file_path: str, ext: str) -> Tuple[bool, str]:
    """Validates magic bytes, structural integrity, and safety bounds for all supported formats."""
    ext = (ext or '').lower().lstrip('.')
    if not is_supported_extension(ext):
        return False, f"Unsupported file extension .{ext}."

    if not os.path.isfile(file_path):
        return False, "Uploaded file could not be found on server."

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return False, "File is empty (0 bytes)."

    category = get_format_category(ext)

    try:
        with open(file_path, 'rb') as f:
            header = f.read(32)

        if category == 'pdf':
            if len(header) < 5 or not header.startswith(b'%PDF-'):
                return False, "Invalid PDF structure: missing %PDF- header."
            doc = pymupdf.open(file_path)
            page_count = len(doc)
            doc.close()
            if page_count == 0:
                return False, "Invalid PDF: document contains 0 pages."
            if page_count > MAX_PDF_PAGES:
                return False, f"PDF exceeds maximum page limit (found {page_count} pages, limit is {MAX_PDF_PAGES})."
            return True, ""

        if category == 'image':
            if ext == 'png' and not header.startswith(b'\x89PNG\r\n\x1a\n'):
                return False, "Invalid PNG file: corrupted header."
            elif ext in ('jpg', 'jpeg') and not header.startswith(b'\xff\xd8\xff'):
                return False, "Invalid JPEG file: corrupted header."
            elif ext == 'webp' and not (header.startswith(b'RIFF') and b'WEBP' in header[:16]):
                return False, "Invalid WEBP file: corrupted header."
            elif ext == 'bmp' and not header.startswith(b'BM'):
                return False, "Invalid BMP file: corrupted header."
            elif ext in ('tiff', 'tif') and not (header.startswith(b'II*\x00') or header.startswith(b'MM\x00*')):
                return False, "Invalid TIFF file: corrupted header."
            elif ext == 'gif' and not (header.startswith(b'GIF87a') or header.startswith(b'GIF89a')):
                return False, "Invalid GIF file: corrupted header."

            with Image.open(file_path) as img:
                img.verify()
            with Image.open(file_path) as img:
                w, h = img.size
                if w <= 0 or h <= 0:
                    return False, "Invalid image dimensions."
            return True, ""

        if category in ('docx', 'pptx', 'xlsx'):
            if len(header) < 4 or not header.startswith(b'PK'):
                return False, f"Invalid .{ext} file: not a valid Office Open XML archive."
            if not zipfile.is_zipfile(file_path):
                return False, f"Corrupted .{ext} archive."
            with zipfile.ZipFile(file_path, 'r') as zf:
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                if total_uncompressed > MAX_OFFICE_UNCOMPRESSED_BYTES:
                    return False, f"Office document exceeds uncompressed safety limit ({MAX_OFFICE_UNCOMPRESSED_BYTES // (1024*1024)} MB)."
                names = set(zf.namelist())
                if '[Content_Types].xml' not in names:
                    return False, f"Invalid .{ext} structure: missing [Content_Types].xml."

            if category == 'docx':
                import docx
                doc = docx.Document(file_path)
                _ = len(doc.paragraphs)
            elif category == 'pptx':
                import pptx
                prs = pptx.Presentation(file_path)
                _ = len(prs.slides)
            elif category == 'xlsx':
                import openpyxl
                wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
                _ = len(wb.sheetnames)
                wb.close()
            return True, ""

        if category in ('text', 'csv'):
            if file_size > MAX_TEXT_BYTES:
                return False, f"Text file exceeds maximum limit ({MAX_TEXT_BYTES // (1024*1024)} MB)."
            with open(file_path, 'rb') as f:
                raw = f.read()
            if b'\x00' in raw:
                return False, f"Invalid .{ext} file: binary/null bytes detected."
            try:
                raw.decode('utf-8-sig')
            except UnicodeDecodeError:
                try:
                    raw.decode('latin-1')
                except UnicodeDecodeError:
                    return False, f"Unable to decode .{ext} file as text."
            return True, ""

        return False, f"Unsupported file category for .{ext}."
    except Exception as e:
        return False, f"Failed to validate .{ext} file: {str(e)}"
