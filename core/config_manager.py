"""
ShareSafe Configuration Manager
Manages runtime settings such as custom Tesseract executable paths and engine preferences.
"""

import os
import shutil
from pathlib import Path

# Common Tesseract executable paths on Windows and Linux
COMMON_WINDOWS_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
    os.path.expandvars(r"%USERPROFILE%\scoop\apps\tesseract\current\tesseract.exe"),
    r"C:\ProgramData\chocolatey\bin\tesseract.exe",
]

COMMON_UNIX_PATHS = [
    "/usr/bin/tesseract",
    "/usr/local/bin/tesseract",
    "/opt/homebrew/bin/tesseract",
]

_custom_tesseract_path = None

def get_tesseract_config():
    """
    Returns the resolved tesseract executable path and availability status.
    """
    global _custom_tesseract_path
    
    # 1. Check in-memory custom configuration
    if _custom_tesseract_path and os.path.isfile(_custom_tesseract_path):
        return {
            "path": _custom_tesseract_path,
            "available": True,
            "source": "custom_override"
        }
    
    # 2. Check environment variable
    env_path = os.environ.get("TESSERACT_CMD", "").strip()
    if env_path and os.path.isfile(env_path):
        return {
            "path": env_path,
            "available": True,
            "source": "environment_variable"
        }
    
    # 3. Check system PATH
    which_path = shutil.which("tesseract") or shutil.which("tesseract.exe")
    if which_path and os.path.isfile(which_path):
        return {
            "path": which_path,
            "available": True,
            "source": "system_path"
        }
    
    # 4. Check known Windows paths
    if os.name == "nt":
        for p in COMMON_WINDOWS_PATHS:
            if os.path.isfile(p):
                return {
                    "path": p,
                    "available": True,
                    "source": "auto_discovered_windows"
                }
    else:
        for p in COMMON_UNIX_PATHS:
            if os.path.isfile(p):
                return {
                    "path": p,
                    "available": True,
                    "source": "auto_discovered_unix"
                }
    
    return {
        "path": None,
        "available": False,
        "source": "none"
    }

def set_tesseract_config(path: str):
    """
    Set a user-specified path to the tesseract executable.
    """
    global _custom_tesseract_path
    clean_path = path.strip().strip('"').strip("'")
    if clean_path and os.path.isfile(clean_path):
        _custom_tesseract_path = clean_path
        return True, f"Tesseract path updated to: {clean_path}"
    elif not clean_path:
        _custom_tesseract_path = None
        return True, "Custom Tesseract path reset."
    else:
        return False, f"File not found at path: {clean_path}"
