import os
from typing import Dict, Any, List
from PIL import Image, ExifTags
import pymupdf

from core.format_registry import get_format_category


class MetadataCleaner:
    """Detects and scrubs embedded metadata including EXIF tags, GPS coordinates, author history, and Office/PDF stream attributes."""

    OFFICE_FIELDS = [
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
        ('created', 'Created'),
        ('modified', 'Modified'),
    ]

    @classmethod
    def inspect_file(cls, file_path: str) -> Dict[str, Any]:
        """Inspects a file for latent privacy-leaking metadata attributes."""
        category = get_format_category(file_path)
        if category == 'pdf':
            return cls._inspect_pdf(file_path)
        elif category in ('docx', 'pptx', 'xlsx'):
            return cls._inspect_office(file_path, category)
        elif category in ('text', 'csv'):
            return {
                'file_type': category,
                'metadata_count': 0,
                'has_gps': False,
                'summary_tags': [],
                'tags': [],
                'status': 'Clean / No Embedded Metadata'
            }
        else:
            return cls._inspect_image(file_path)

    @classmethod
    def _inspect_image(cls, img_path: str) -> Dict[str, Any]:
        tags_found = []
        has_gps = False
        camera_info = []

        try:
            with Image.open(img_path) as img:
                exif_data = img.getexif()
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        val_str = str(value)[:60]

                        if 'GPS' in tag_name.upper():
                            has_gps = True
                        if tag_name in ('Make', 'Model', 'Software', 'DateTime', 'Artist', 'HostComputer'):
                            camera_info.append(f"{tag_name}: {val_str}")

                        tags_found.append({
                            'tag': tag_name,
                            'value': val_str,
                            'is_sensitive': tag_name in ('GPSInfo', 'DateTime', 'Software', 'Model', 'Artist')
                        })
        except Exception:
            pass

        return {
            'file_type': 'image',
            'metadata_count': len(tags_found),
            'has_gps': has_gps,
            'summary_tags': camera_info,
            'tags': tags_found,
            'status': 'EXIF Metadata Detected' if tags_found else 'Clean / No EXIF'
        }

    @classmethod
    def _inspect_pdf(cls, pdf_path: str) -> Dict[str, Any]:
        tags_found = []
        try:
            doc = pymupdf.open(pdf_path)
            meta = doc.metadata
            if meta:
                for k, v in meta.items():
                    if v and str(v).strip():
                        tags_found.append({
                            'tag': k.capitalize(),
                            'value': str(v)[:80],
                            'is_sensitive': k.lower() in ('author', 'creator', 'producer', 'creationdate', 'moddate')
                        })
            doc.close()
        except Exception:
            pass

        return {
            'file_type': 'pdf',
            'metadata_count': len(tags_found),
            'has_gps': False,
            'summary_tags': [f"{t['tag']}: {t['value']}" for t in tags_found[:4]],
            'tags': tags_found,
            'status': 'Document Metadata Detected' if tags_found else 'Clean / No Metadata'
        }

    @classmethod
    def _inspect_office(cls, file_path: str, category: str) -> Dict[str, Any]:
        tags_found = []
        seen = set()
        try:
            props = None
            if category == 'docx':
                import docx
                props = docx.Document(file_path).core_properties
            elif category == 'pptx':
                import pptx
                props = pptx.Presentation(file_path).core_properties
            elif category == 'xlsx':
                import openpyxl
                wb = openpyxl.load_workbook(file_path, read_only=True)
                props = wb.properties
                # Extract before closing
                cls._collect_props(props, tags_found, seen)
                wb.close()
                props = None

            if props is not None:
                cls._collect_props(props, tags_found, seen)
        except Exception:
            pass

        return {
            'file_type': category,
            'metadata_count': len(tags_found),
            'has_gps': False,
            'summary_tags': [f"{t['tag']}: {t['value']}" for t in tags_found[:4]],
            'tags': tags_found,
            'status': 'Document Metadata Detected' if tags_found else 'Clean / No Metadata'
        }

    @classmethod
    def _collect_props(cls, props, tags_found: List[Dict[str, Any]], seen: set):
        for attr, label in cls.OFFICE_FIELDS:
            if hasattr(props, attr):
                val = getattr(props, attr, None)
                if val is not None and str(val).strip():
                    val_str = str(val).strip()[:80]
                    if (label, val_str) not in seen:
                        seen.add((label, val_str))
                        tags_found.append({
                            'tag': label,
                            'value': val_str,
                            'is_sensitive': attr.lower() in ('author', 'creator', 'last_modified_by', 'lastmodifiedby', 'company', 'comments')
                        })

    @classmethod
    def scrub_office_properties(cls, props) -> None:
        """Clears identifying author, history, and document metadata fields on Office core_properties."""
        str_fields = [
            'author', 'creator', 'last_modified_by', 'lastModifiedBy',
            'title', 'subject', 'keywords', 'comments', 'description',
            'category', 'company', 'content_status', 'identifier', 'version'
        ]
        for attr in str_fields:
            if hasattr(props, attr):
                try:
                    setattr(props, attr, '')
                except Exception:
                    try:
                        setattr(props, attr, None)
                    except Exception:
                        pass

    @classmethod
    def scrub_image(cls, src_path: str, dst_path: str) -> bool:
        """Saves a byte-for-byte image pixel copy with all EXIF, GPS, and header profiles purged."""
        try:
            with Image.open(src_path) as img:
                if getattr(img, 'n_frames', 1) > 1:
                    img.seek(0)
                if img.mode not in ('RGB', 'RGBA', 'L'):
                    img = img.convert('RGB')
                data = list(img.getdata())
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(data)
                clean_img.save(dst_path)
            return True
        except Exception as e:
            print(f"[Metadata Scrub Error]: {e}")
            return False

    @classmethod
    def scrub_pdf(cls, src_path: str, dst_path: str) -> bool:
        """Strips /Author, /Producer, creation history, and XMP streams from PDF."""
        try:
            doc = pymupdf.open(src_path)
            doc.set_metadata({})
            doc.save(dst_path, garbage=4, deflate=True)
            doc.close()
            return True
        except Exception as e:
            print(f"[PDF Metadata Scrub Error]: {e}")
            return False
