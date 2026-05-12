import psutil
import os
import threading
import time
from src.utils.logger import logger

class ProcessCache:
    """
    Maintains a mapping of open files to PIDs to avoid expensive psutil iterations on every event.
    """
    def __init__(self, refresh_interval=1.0):
        self.file_to_pid = {}
        self.refresh_interval = refresh_interval
        self.running = False
        self._lock = threading.Lock()

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _refresh_loop(self):
        while self.running:
            try:
                new_mapping = {}
                for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                    try:
                        if not proc.info['open_files']:
                            continue
                        for f in proc.info['open_files']:
                            path = os.path.normpath(f.path)
                            new_mapping[path] = (proc.info['pid'], proc.info['name'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                with self._lock:
                    self.file_to_pid = new_mapping
            except Exception as e:
                logger.error(f"Error refreshing process cache: {e}")
            time.sleep(self.refresh_interval)

    def get_pid_for_file(self, filepath: str):
        filepath = os.path.normpath(filepath)
        with self._lock:
            return self.file_to_pid.get(filepath, (None, None))

# Global cache instance
process_cache = ProcessCache()

def get_process_using_file(filepath: str):
    """
    Uses the optimized ProcessCache to find the PID for a file.
    """
    return process_cache.get_pid_for_file(filepath)

def kill_process(pid: int):
    """
    Terminates a process by PID.
    """
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
        return True
    except Exception as e:
        logger.error(f"Failed to kill process {pid}: {e}")
        return False
