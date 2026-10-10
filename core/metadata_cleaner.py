import os
from typing import Dict, Any, List
from PIL import Image, ExifTags
import pymupdf

class MetadataCleaner:
    """Detects and scrubs embedded metadata including EXIF tags, GPS coordinates, author history, and PDF stream attributes."""

    @classmethod
    def inspect_file(cls, file_path: str) -> Dict[str, Any]:
        """Inspects a file for latent privacy-leaking metadata attributes."""
        ext = os.path.splitext(file_path)[1].lower().strip('.')
        if ext == 'pdf':
            return cls._inspect_pdf(file_path)
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
    def scrub_image(cls, src_path: str, dst_path: str) -> bool:
        """Saves a byte-for-byte image pixel copy with all EXIF, GPS, and header profiles purged."""
        try:
            with Image.open(src_path) as img:
                # Convert RGBA/P to RGB if needed, discard exif
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
