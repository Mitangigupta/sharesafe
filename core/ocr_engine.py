import os
import shutil
import subprocess
import json
import tempfile
import sys
import re
from typing import List, Dict, Any, Optional, Tuple
from PIL import Image
from config import Config

class OCREngine:
    """Multi-backend OCR engine supporting native Windows Media OCR and PyTesseract.
    Provides out-of-the-box OCR on Windows without requiring manual external binary installs.
    """

    def __init__(self):
        self._tesseract_path: Optional[str] = Config.TESSERACT_CMD
        self._pytesseract_module = None
        self._has_windows_ocr = False
        self._win_ocr_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'win_ocr.ps1')

        self._init_pytesseract()
        self._init_windows_ocr()

    def _init_pytesseract(self):
        try:
            import pytesseract
            self._pytesseract_module = pytesseract
            if self._tesseract_path and os.path.isfile(self._tesseract_path):
                self._pytesseract_module.pytesseract.tesseract_cmd = self._tesseract_path
        except ImportError:
            self._pytesseract_module = None

    def _init_windows_ocr(self):
        if sys.platform == 'win32' and os.path.isfile(self._win_ocr_script):
            # Test if Windows Media OCR runtime is available
            try:
                cmd = [
                    'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                    '-Command',
                    '[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null; $e = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages(); if ($e) { "OK" }'
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if 'OK' in res.stdout:
                    self._has_windows_ocr = True
            except Exception:
                self._has_windows_ocr = False

    def set_tesseract_path(self, path: str) -> Tuple[bool, str]:
        """Sets and tests a new Tesseract binary path at runtime."""
        if not path or not os.path.isfile(path):
            return False, f"File does not exist: {path}"
        try:
            if not self._pytesseract_module:
                import pytesseract
                self._pytesseract_module = pytesseract

            self._pytesseract_module.pytesseract.tesseract_cmd = path
            version = self._pytesseract_module.get_tesseract_version()
            self._tesseract_path = path
            Config.TESSERACT_CMD = path
            return True, f"Tesseract OCR {version} successfully connected!"
        except Exception as e:
            return False, f"Failed to initialize Tesseract at {path}: {str(e)}"

    def get_status(self) -> Dict[str, Any]:
        """Returns the operational status of the OCR subsystem."""
        # Check Tesseract first
        if self._pytesseract_module and self._tesseract_path:
            try:
                version = str(self._pytesseract_module.get_tesseract_version())
                return {
                    'available': True,
                    'engine': 'tesseract',
                    'path': self._tesseract_path,
                    'version': version,
                    'message': f"Tesseract OCR {version} is active and ready."
                }
            except Exception:
                pass

        # Check Windows Native Media OCR
        if self._has_windows_ocr:
            return {
                'available': True,
                'engine': 'windows_media_ocr',
                'path': 'Windows 10/11 Built-in Runtime',
                'version': 'WinRT-Media-OCR',
                'message': "Windows Native Media OCR is active and ready (Zero-dependency)."
            }

        return {
            'available': False,
            'engine': 'none',
            'path': self._tesseract_path,
            'version': None,
            'message': "Tesseract OCR binary not found. Digital PDFs work 100% via PyMuPDF native vector extraction."
        }

    def is_available(self) -> bool:
        status = self.get_status()
        return status['available']

    def extract_words_and_boxes(self, pil_image: Image.Image, img_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extracts individual words and their pixel bounding boxes [x, y, w, h]."""
        if pil_image is None and img_path and os.path.isfile(img_path):
            try:
                pil_image = Image.open(img_path)
            except Exception:
                return []

        if pil_image is None:
            return []

        # Normalize mode for OCR
        proc_img = pil_image
        if proc_img.mode in ('RGBA', 'LA', 'P'):
            bg = Image.new('RGB', proc_img.size, (255, 255, 255))
            if proc_img.mode == 'RGBA':
                bg.paste(proc_img, mask=proc_img.split()[3])
            else:
                bg.paste(proc_img.convert('RGB'))
            proc_img = bg
        elif proc_img.mode != 'RGB':
            proc_img = proc_img.convert('RGB')

        w, h = proc_img.size
        # Contrast optimization for faint or low-contrast document scans
        try:
            from PIL import ImageOps
            gray = proc_img.convert('L')
            extrema = gray.getextrema()
            if extrema and (extrema[1] - extrema[0] < 190):
                enhanced = ImageOps.autocontrast(proc_img, cutoff=1)
                proc_img = enhanced
        except Exception:
            pass

        # Adaptive upscaling for small images / screenshots to ensure small fonts (8-14px) are OCR-readable
        scale = 1.0
        if min(w, h) < 1200 or max(w, h) < 1800:
            scale = 2.0
            new_w = int(round(w * scale))
            new_h = int(round(h * scale))
            proc_img = proc_img.resize((new_w, new_h), Image.Resampling.LANCZOS)

        # 1. Try Windows Media OCR if available (fastest on Windows, zero installation)
        words = []
        if self._has_windows_ocr:
            target_path = img_path if (scale == 1.0 and img_path and os.path.isfile(img_path) and pil_image.mode == 'RGB') else None
            words = self._extract_via_windows_ocr(proc_img, target_path)

        # 2. Try Tesseract if Windows OCR produced no words
        if not words and self._pytesseract_module and self._tesseract_path:
            words = self._extract_via_tesseract(proc_img)

        # Scale bounding boxes back to original image coordinates
        if scale != 1.0 and words:
            for item in words:
                if 'bbox' in item and len(item['bbox']) == 4:
                    item['bbox'] = [
                        round(item['bbox'][0] / scale, 1),
                        round(item['bbox'][1] / scale, 1),
                        round(item['bbox'][2] / scale, 1),
                        round(item['bbox'][3] / scale, 1)
                    ]

        return words

    def _extract_via_tesseract(self, pil_image: Image.Image) -> List[Dict[str, Any]]:
        """Extracts words and bounding boxes via PyTesseract."""
        try:
            data = self._pytesseract_module.image_to_data(pil_image, output_type=self._pytesseract_module.Output.DICT)
            results = []
            n_boxes = len(data['text'])
            for i in range(n_boxes):
                text = data['text'][i].strip()
                if not text:
                    continue
                conf = float(data['conf'][i])
                if conf < 10.0:
                    continue

                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                results.append({
                    'text': text,
                    'bbox': [x, y, w, h],
                    'conf': conf,
                    'line_num': data['line_num'][i],
                    'block_num': data['block_num'][i]
                })
            return results
        except Exception as e:
            print(f"[OCREngine Tesseract Error]: {e}")
            return []

    def _extract_via_windows_ocr(self, pil_image: Image.Image, img_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Calls the native Windows Media OCR PowerShell bridge."""
        temp_file = None
        target_path = img_path

        try:
            if not target_path or not os.path.isfile(target_path):
                # Save PIL image to a temporary file
                fd, temp_file = tempfile.mkstemp(suffix='.png')
                os.close(fd)
                pil_image.save(temp_file, format='PNG')
                target_path = temp_file

            cmd = [
                'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', self._win_ocr_script,
                '-ImagePath', target_path
            ]
            run_res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if run_res.returncode == 0 and run_res.stdout.strip():
                out_str = run_res.stdout.strip()
                # Sanitize non-printable control characters that OCR might produce
                cleaned_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', out_str)
                # Parse json from output
                try:
                    words = json.loads(cleaned_str, strict=False)
                    if isinstance(words, list):
                        return words
                except json.JSONDecodeError:
                    # In case of any surrounding non-json output, isolate array slice
                    start = cleaned_str.find('[')
                    end = cleaned_str.rfind(']')
                    if start != -1 and end != -1:
                        return json.loads(cleaned_str[start:end+1], strict=False)

        except Exception as e:
            print(f"[Windows Media OCR Error]: {e}")
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass

        return []

    def extract_full_text(self, pil_image: Image.Image, img_path: Optional[str] = None) -> str:
        """Extracts plain text from image."""
        words = self.extract_words_and_boxes(pil_image, img_path)
        if words:
            return " ".join([w['text'] for w in words])
        return ""

# Global OCR singleton instance
ocr_engine = OCREngine()
