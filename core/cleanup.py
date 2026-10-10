import os
import shutil
import time
from config import Config

class SessionManager:
    """Manages secure ephemeral session storage with automated TTL purging and immediate memory wipe."""

    @classmethod
    def get_session_upload_dir(cls, session_id: str) -> str:
        path = os.path.join(Config.UPLOAD_FOLDER, session_id)
        os.makedirs(path, exist_ok=True)
        return path

    @classmethod
    def get_session_output_dir(cls, session_id: str) -> str:
        path = os.path.join(Config.OUTPUT_FOLDER, session_id)
        os.makedirs(path, exist_ok=True)
        return path

    @classmethod
    def purge_session(cls, session_id: str) -> bool:
        """Immediately destroys all session data on disk."""
        import gc
        gc.collect()  # Release any uncollected file handles

        success = True
        for base in (Config.UPLOAD_FOLDER, Config.OUTPUT_FOLDER):
            target = os.path.join(base, session_id)
            if os.path.exists(target):
                # Try removal with brief retry for Windows file locks
                removed = False
                for attempt in range(3):
                    try:
                        shutil.rmtree(target)
                        removed = True
                        break
                    except Exception as e:
                        time.sleep(0.05)
                        gc.collect()
                if not removed:
                    success = False
        return success

    @classmethod
    def cleanup_old_sessions(cls, max_age_minutes: int = Config.SESSION_TTL_MINUTES):
        """Scans session directories and purges anything older than max_age_minutes."""
        now = time.time()
        max_age_sec = max_age_minutes * 60

        for base in (Config.UPLOAD_FOLDER, Config.OUTPUT_FOLDER):
            if not os.path.exists(base):
                continue
            for entry in os.listdir(base):
                entry_path = os.path.join(base, entry)
                if os.path.isdir(entry_path):
                    try:
                        mtime = os.path.getmtime(entry_path)
                        if (now - mtime) > max_age_sec:
                            shutil.rmtree(entry_path)
                    except Exception:
                        pass
