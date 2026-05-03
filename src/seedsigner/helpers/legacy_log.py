import logging
import os
import subprocess

_LOG_MOUNT = "/mnt/boot"
_LOG_PATH = "/mnt/boot/legacy.log"
_mounted = False


def _ensure_mounted():
    global _mounted
    if _mounted:
        return True
    # Try the already-mounted boot path first (SeedSigner OS mounts it at /boot).
    for candidate in ("/boot", _LOG_MOUNT):
        if os.path.isdir(candidate) and os.access(candidate, os.W_OK):
            global _LOG_PATH
            _LOG_PATH = candidate + "/legacy.log"
            _mounted = True
            return True
    # Fall back to mounting the FAT partition ourselves.
    try:
        os.makedirs(_LOG_MOUNT, exist_ok=True)
        result = subprocess.run(
            ["mount", "-t", "vfat", "/dev/mmcblk0p1", _LOG_MOUNT],
            capture_output=True,
            timeout=5,
        )
        _mounted = result.returncode == 0
    except Exception:
        pass
    return _mounted


class _SyncFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        try:
            os.fsync(self.stream.fileno())
        except Exception:
            pass


def get_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        _ensure_mounted()
        try:
            fh = _SyncFileHandler(_LOG_PATH)
            fh.setFormatter(
                logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
            )
            log.addHandler(fh)
            log.setLevel(logging.DEBUG)
        except Exception:
            log.addHandler(logging.NullHandler())
    return log
