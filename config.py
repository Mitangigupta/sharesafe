import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Vercel's serverless filesystem is read-only except for /tmp
RUNTIME_DIR = Path('/tmp/sharesafe') if os.environ.get('VERCEL') else BASE_DIR

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'sharesafe-secret-key-cyber-guard-2026')
    UPLOAD_FOLDER = os.path.join(RUNTIME_DIR, 'uploads')
    OUTPUT_FOLDER = os.path.join(RUNTIME_DIR, 'outputs')
    SAMPLES_FOLDER = os.path.join(BASE_DIR, 'samples')
    MAX_CONTENT_LENGTH = 30 * 1024 * 1024  # 30 MB max upload
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp', 'pdf'}
    SESSION_TTL_MINUTES = 30
    SEND_FILE_MAX_AGE_DEFAULT = 0

    # Auto-detect Tesseract OCR executable on Windows and Linux/macOS
    _tess_env = os.environ.get('TESSERACT_CMD')
    _tess_candidates = [
        _tess_env,
        shutil.which('tesseract'),
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
        os.path.expandvars(r"%USERPROFILE%\scoop\apps\tesseract\current\tesseract.exe"),
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
        "/opt/homebrew/bin/tesseract"
    ]
    
    TESSERACT_CMD = None
    for cand in _tess_candidates:
        if cand and os.path.isfile(cand):
            TESSERACT_CMD = cand
            break

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.OUTPUT_FOLDER, exist_ok=True)
if not os.environ.get('VERCEL'):
    os.makedirs(Config.SAMPLES_FOLDER, exist_ok=True)
