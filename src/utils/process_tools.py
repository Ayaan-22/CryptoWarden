"""Process-instance inspection. Never infer a writer from system-wide IO."""

import hashlib

import psutil

from src.config import normalize_path
from src.models import ProcessIdentity


def inspect_process(pid):
    if type(pid) is not int or pid <= 0:
        return None
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            identity = ProcessIdentity(
                pid, process.create_time(), process.name(), normalize_path(process.exe())
            )
        return identity if process.is_running() else None
    except (psutil.Error, OSError):
        return None


def executable_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class ProcessCache:
    """Deprecated compatibility facade. Open-file enumeration cannot prove writes."""

    def __init__(self, refresh_interval=1):
        self.running = False
        self.tracker = None
        self.file_to_pid = {}
        self.history = {}

    def start(self):
        self.running = True

    def stop(self):
        self.running = False
        self.file_to_pid.clear()
        self.history.clear()

    def get_pid_for_file(self, filepath, allow_direct_lookup=False):
        return None, None

    def get_recent_top_writer(self, max_age=0):
        return None, None


process_cache = ProcessCache()


def get_process_using_file(filepath, allow_direct_lookup=False):
    return None, None


def get_recent_writer_candidate():
    return None, None


def kill_process(pid):
    """Unsafe PID-only API removed. Use Responder with a captured ProcessIdentity."""
    raise ValueError("PID-only termination is not supported")
