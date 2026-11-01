"""Fresh process-instance state and bounded unique-file windows."""

import time
from collections import deque

from src.config import config, normalize_path


class ProcessState:
    def __init__(self, pid, name, create_time=None, window=None, clock=time.monotonic):
        self.pid, self.name, self.create_time = pid, name, create_time
        self.window = window or config["detection"]["window_seconds"]
        self.clock = clock
        self.file_modifications = deque(maxlen=20000)
        self.renames = deque(maxlen=20000)
        self.entropy_history = deque(maxlen=32)
        self.io_write_rate = self.io_bytes_rate = 0.0
        self.io_seen = 0.0
        self.last_seen = self.clock()

    def update_io_stats(self, rate, bytes_rate=0, now=None):
        self.io_write_rate = max(0, rate)
        self.io_bytes_rate = max(0, bytes_rate)
        self.io_seen = self.clock() if now is None else now
        self.last_seen = self.io_seen

    def add_modification(self, timestamp=None, path=None):
        now = self.clock()
        self.file_modifications.append((now, normalize_path(path) if path else f"legacy-{now}"))
        self.last_seen = now
        self.prune(now)

    def add_rename(self, timestamp=None, path=None):
        now = self.clock()
        self.renames.append((now, normalize_path(path) if path else f"legacy-{now}"))
        self.last_seen = now
        self.prune(now)

    def add_entropy_sample(self, value):
        self.entropy_history.append((self.clock(), value))

    def prune(self, now=None):
        now = self.clock() if now is None else now
        for events in (self.file_modifications, self.renames, self.entropy_history):
            while events and now - events[0][0] >= self.window:
                events.popleft()
        if now - self.io_seen > 3:
            self.io_write_rate = self.io_bytes_rate = 0.0

    def unique_modifications(self):
        self.prune()
        return len({path for _, path in self.file_modifications})

    def unique_renames(self):
        self.prune()
        return len({path for _, path in self.renames})

    def get_modification_rate(self):
        return self.unique_modifications() / self.window


class ProcessTracker:
    def __init__(self, window=None, clock=time.monotonic):
        self.processes = {}
        self.window, self.clock = window, clock

    def get_or_create(self, pid, name, create_time=None):
        state = self.processes.get(pid)
        if state is None or state.create_time != create_time or state.name != name:
            state = ProcessState(pid, name, create_time, self.window, self.clock)
            self.processes[pid] = state
        return state

    def update_access(self, pid, name, event_type, timestamp=None, path=None, create_time=None):
        state = self.get_or_create(pid, name, create_time)
        if event_type in {"modified", "created"}:
            state.add_modification(path=path)
        elif event_type == "moved":
            state.add_rename(path=path)
        return state

    def expire(self, active=None):
        now = self.clock()
        for pid, state in list(self.processes.items()):
            state.prune(now)
            if (
                active is not None and (pid, state.create_time) not in active
            ) or now - state.last_seen > 120:
                self.processes.pop(pid, None)
        if len(self.processes) > 4096:
            for pid in sorted(self.processes, key=lambda p: self.processes[p].last_seen)[
                : len(self.processes) - 4096
            ]:
                self.processes.pop(pid, None)

    def get_top_io_processes(self, limit=3):
        self.expire()
        return sorted(
            ((s.pid, s.io_write_rate) for s in self.processes.values() if s.io_write_rate > 0),
            key=lambda item: item[1],
            reverse=True,
        )[:limit]

    def get_process_name(self, pid):
        return self.processes[pid].name if pid in self.processes else "Unknown"
