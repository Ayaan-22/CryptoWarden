import psutil
import os
import threading
import time
from src.utils.logger import logger

class ProcessCache:
    """
    Maintains a mapping of open files to PIDs to avoid expensive psutil iterations on every event.
    """
    def __init__(self, refresh_interval=0.5):
        self.file_to_pid = {}
        self.history = {} # Keep history of recently seen files
        self.refresh_interval = refresh_interval
        self.running = False
        self._lock = threading.Lock()
        self.tracker = None
        self.last_write_counts = {}
        self.recent_writers = []

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
                active_writers = []
                now = time.time()
                from src.config import is_whitelisted_process
                for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        io = proc.info['io_counters']
                        
                        if not name or not io:
                            continue
                            
                        # Skip whitelisted processes
                        if is_whitelisted_process(name):
                            continue
                            
                        # Check if write_count increased since the previous loop.
                        curr_writes = io.write_count + (getattr(io, "write_bytes", 0) / 4096)
                        prev_writes = self.last_write_counts.get(pid)
                        self.last_write_counts[pid] = curr_writes
                        
                        if prev_writes is not None and curr_writes > prev_writes:
                            active_writers.append((curr_writes - prev_writes, pid, name, now))
                            files = proc.open_files()
                            if files:
                                for f in files:
                                    path = os.path.normpath(f.path)
                                    new_mapping[path] = (pid, name)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                with self._lock:
                    self.history.update(self.file_to_pid)
                    if len(self.history) > 1000:
                        self.history = dict(list(self.history.items())[-500:])
                    self.file_to_pid.update(new_mapping)
                    if len(self.file_to_pid) > 2000:
                        self.file_to_pid = dict(list(self.file_to_pid.items())[-1000:])
                    self.recent_writers = [
                        writer for writer in self.recent_writers
                        if now - writer[3] <= 3
                    ]
                    self.recent_writers.extend(active_writers)
                    self.recent_writers.sort(key=lambda writer: writer[0], reverse=True)
                    self.recent_writers = self.recent_writers[:20]
            except Exception as e:
                logger.error(f"Error refreshing process cache: {e}")
            time.sleep(self.refresh_interval)

    def get_pid_for_file(self, filepath: str, allow_direct_lookup: bool = True):
        filepath = os.path.normpath(filepath)
        with self._lock:
            # Check current mapping
            res = self.file_to_pid.get(filepath)
            if res: return res
            
            # Check history (in case file was just closed)
            res = self.history.get(filepath)
            if res: return res
            
        # Fallback: Direct check for the specific file (expensive but necessary on cache miss)
        if allow_direct_lookup:
            return self._direct_lookup(filepath)
        return (None, None)

    def _direct_lookup(self, filepath: str):
        try:
            from src.config import is_whitelisted_process
            filepath = os.path.normpath(filepath)
            pids_to_check = []
            if self.tracker:
                top_pids = [pid for pid, _rate in self.tracker.get_top_io_processes(limit=5)]
                recent_writer_pids = [
                    pid for pid in self.tracker.processes
                    if pid not in top_pids and self.last_write_counts.get(pid, 0) > 0
                ][:5]
                pids_to_check = top_pids + recent_writer_pids
                
            # Check currently tracked processes first, prioritizing active writers.
            for pid in pids_to_check:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    if is_whitelisted_process(name):
                        continue
                    files = proc.open_files()
                    if files:
                        for f in files:
                            if os.path.normpath(f.path) == filepath:
                                return (pid, name)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        return (None, None)

    def get_recent_top_writer(self, max_age=3):
        now = time.time()
        with self._lock:
            for _delta, pid, name, seen_at in self.recent_writers:
                if now - seen_at <= max_age:
                    return (pid, name)
        return (None, None)

# Global cache instance
process_cache = ProcessCache()

def get_process_using_file(filepath: str, allow_direct_lookup: bool = True):
    """
    Uses the optimized ProcessCache to find the PID for a file.
    """
    return process_cache.get_pid_for_file(filepath, allow_direct_lookup=allow_direct_lookup)

def get_recent_writer_candidate():
    return process_cache.get_recent_top_writer()

def get_process_by_cmdline_token(token: str):
    token = (token or "").casefold()
    if not token:
        return (None, None)

    try:
        from src.config import is_whitelisted_process
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info['name']
                if not name or is_whitelisted_process(name):
                    continue
                cmdline = " ".join(proc.info.get('cmdline') or []).casefold()
                if token in cmdline:
                    return (proc.info['pid'], name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    return (None, None)

def kill_process(pid: int):
    """
    Terminates a process by PID.
    """
    try:
        proc = psutil.Process(pid)
        proc.kill()
        return True
    except psutil.NoSuchProcess:
        return True
    except Exception as e:
        logger.error(f"Failed to kill process {pid}: {e}")
        return False
