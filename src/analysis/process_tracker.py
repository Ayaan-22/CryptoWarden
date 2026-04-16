import time
from collections import deque
from src.config import MAX_FILE_MODIFICATIONS_PER_SEC

class ProcessState:
    def __init__(self, pid, name):
        self.pid = pid
        self.name = name
        self.file_modifications = deque() # timestamps
        self.renames = deque() # timestamps
        self.entropy_history = [] # list of (timestamp, entropy_val)
        self.accessed_dirs = set()
        self.extension_changes = 0
        self.suspicion_score = 0.0
        self.io_write_rate = 0.0

    def update_io_stats(self, rate):
        self.io_write_rate = rate

    def add_modification(self, timestamp):
        self.file_modifications.append(timestamp)
        self._cleanup_old_events(timestamp)
    
    def add_rename(self, timestamp):
        self.renames.append(timestamp)
        self.extension_changes += 1
        self._cleanup_old_events(timestamp)

    def add_entropy_sample(self, val):
        self.entropy_history.append((time.time(), val))
        if len(self.entropy_history) > 20:
            self.entropy_history.pop(0)

    def _cleanup_old_events(self, current_time, window=10):
        # Remove events older than 10 seconds
        while self.file_modifications and (current_time - self.file_modifications[0] > window):
            self.file_modifications.popleft()
        while self.renames and (current_time - self.renames[0] > window):
            self.renames.popleft()

    def get_modification_rate(self):
        # Returns mods per second roughly
        if not self.file_modifications:
            return 0
        return len(self.file_modifications)

class ProcessTracker:
    def __init__(self):
        self.processes = {} # pid -> ProcessState

    def get_or_create(self, pid, name):
        if pid not in self.processes:
            self.processes[pid] = ProcessState(pid, name)
        return self.processes[pid]

    def update_access(self, pid, name, event_type, timestamp):
        if pid is None:
            return None
        
        proc = self.get_or_create(pid, name)
        
        if event_type == 'modified':
            proc.add_modification(timestamp)
        elif event_type == 'moved':
            proc.add_rename(timestamp)
            
        return proc
