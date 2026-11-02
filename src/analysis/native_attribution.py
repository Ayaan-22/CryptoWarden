"""Bounded, offline ETW correlation experiment. No result is response authorization."""

import ntpath
from dataclasses import asdict, dataclass, replace
from uuid import uuid4


@dataclass(frozen=True)
class NativeEvent:
    generation: str
    timestamp: int  # Raw trace clock ticks, never psutil creation time.
    kind: str
    pid: int = 0
    process_key: int = 0
    tid: int = 0
    file_object: int = 0
    path: str = ""
    size: int = 0


@dataclass(frozen=True)
class TraceProcess:
    generation: str
    pid: int
    process_key: int
    started: int


@dataclass(frozen=True)
class WriteEvidence:
    generation: str
    timestamp: int
    file_object: int
    file_started: int | None
    tid: int
    thread_started: int | None
    path: str | None
    requested_bytes: int
    status: str = "unknown"
    reason: str = "Unresolved native write"
    writer: TraceProcess | None = None


class NativeAttribution:
    """Single-generation replay with final loss checks before releasing any evidence.

    Only observed starts establish lifetimes. Rundown, handles, reads, event-header
    PIDs and current process inspection cannot establish a writer. State is local
    to a replay; it must never be joined to watchdog by path or a time heuristic.
    """

    def __init__(self, *, max_entries=10000, generation=None):
        if type(max_entries) is not int or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        self.generation = generation or str(uuid4())
        self.max_entries = max_entries
        self.processes = {}
        self.threads = {}
        self.files = {}
        self._writes = []
        self._last_timestamp = -1
        self._finished = False
        self.issues = []
        self.loss_notifications = 0

    def mark_loss(self, reason):
        """Any loss taints the entire generation, including earlier correlations.

        ETL loss totals need not identify when loss occurred. Clearing caches or
        seeing a later start is insufficient recovery; begin a new replay instead.
        """
        self.loss_notifications += 1
        if reason not in self.issues and len(self.issues) < 32:
            self.issues.append(reason)
        self.processes.clear()
        self.threads.clear()
        self.files.clear()

    def _invalidate_boundary(self, timestamp, predicate):
        # Equal-clock lifecycle transitions cannot establish event ordering.
        self._writes = [
            replace(row, status="unknown", writer=None, reason="Ambiguous lifetime boundary")
            if row.timestamp == timestamp and predicate(row)
            else row
            for row in self._writes
        ]

    def accept(self, event):
        if self._finished:
            raise RuntimeError("Replay is finalized")
        if event.generation != self.generation:
            self.mark_loss("Collector generation mismatch")
            return
        if type(event.timestamp) is not int or event.timestamp < self._last_timestamp:
            self.mark_loss("Out-of-order or invalid trace timestamp")
            return
        self._last_timestamp = event.timestamp
        if self.issues:
            # Keep bounded UNKNOWN evidence for subsequent writes; never rebuild trust.
            if event.kind == "write":
                self._record_write(event)
            return
        if event.kind == "process_start":
            if not event.pid or not event.process_key or event.pid in self.processes:
                self.mark_loss("Missing or overlapping process lifetime")
                return
            self.processes[event.pid] = TraceProcess(
                self.generation, event.pid, event.process_key, event.timestamp
            )
        elif event.kind == "process_end":
            process = self.processes.get(event.pid)
            if process and process.process_key == event.process_key:
                self._invalidate_boundary(event.timestamp, lambda row: row.writer == process)
                del self.processes[event.pid]
                self.threads = {
                    tid: entry for tid, entry in self.threads.items() if entry[0] != process
                }
            elif process:
                self.mark_loss("Process end does not match process instance")
        elif event.kind == "thread_start":
            if event.tid in self.threads:
                self.mark_loss("Overlapping thread lifetime")
                return
            process = self.processes.get(event.pid)
            if process and event.tid:
                self.threads[event.tid] = (process, event.timestamp)
        elif event.kind == "thread_end":
            entry = self.threads.get(event.tid)
            if entry and entry[0].pid != event.pid:
                self.mark_loss("Thread end does not match process instance")
                return
            self._invalidate_boundary(event.timestamp, lambda row: row.tid == event.tid)
            self.threads.pop(event.tid, None)
        elif event.kind == "file_create":
            if not event.file_object or not event.path or event.file_object in self.files:
                self.mark_loss("Missing or overlapping file-object lifetime")
                return
            self.files[event.file_object] = (event.path, event.timestamp)
        elif event.kind == "file_close":
            self._invalidate_boundary(
                event.timestamp, lambda row: row.file_object == event.file_object
            )
            self.files.pop(event.file_object, None)
        elif event.kind == "file_invalidate":
            # Cleanup/rename/delete/set-info: no path propagation across uncertain changes.
            self._invalidate_boundary(
                event.timestamp, lambda row: row.file_object == event.file_object
            )
            self.files.pop(event.file_object, None)
        elif event.kind == "write":
            self._record_write(event)
        elif event.kind != "read":
            self.mark_loss("Unsupported normalized event")
        if max(len(self.processes), len(self.threads), len(self.files)) > self.max_entries:
            self.mark_loss("Attribution state capacity exceeded")

    def _record_write(self, event):
        if len(self._writes) >= self.max_entries:
            self.mark_loss("Write evidence capacity exceeded")
            return
        file = self.files.get(event.file_object)
        thread = self.threads.get(event.tid)
        process = thread[0] if thread else None
        resolved = (
            not self.issues
            and file
            and thread
            and self.processes.get(process.pid) == process
            and event.timestamp > max(file[1], thread[1], process.started)
            and event.size > 0
        )
        self._writes.append(
            WriteEvidence(
                self.generation,
                event.timestamp,
                event.file_object,
                file[1] if file else None,
                event.tid,
                thread[1] if thread else None,
                file[0] if file else None,
                event.size,
                "native_correlated" if resolved else "unknown",
                "Observed write request and complete lifetimes; unqualified"
                if resolved
                else "Missing, ambiguous or loss-tainted write/lifetime evidence",
                process if resolved else None,
            )
        )

    def finish(self, *, complete):
        if not complete:
            self.mark_loss("Trace processing incomplete")
        self._finished = True

    def writes(self):
        if not self._finished or self.issues:
            reason = "; ".join(self.issues) if self.issues else "Replay not finalized"
            return tuple(
                replace(row, status="unknown", writer=None, reason=reason) for row in self._writes
            )
        return tuple(self._writes)

    def attribute_path(self, path, start, end):
        """Investigation-only query over an explicit trace-clock interval, inclusive.

        Multiple writers or even one unresolved write in the interval are UNKNOWN.
        No nearest writer or highest-I/O fallback is permitted.
        """
        key = ntpath.normcase(ntpath.normpath(path))
        rows = [row for row in self.writes() if start <= row.timestamp <= end]
        matching = [
            row for row in rows if row.path and ntpath.normcase(ntpath.normpath(row.path)) == key
        ]
        writers = {row.writer for row in matching if row.writer}
        if (
            matching
            and len(writers) == 1
            and all(row.status == "native_correlated" for row in matching)
            and all(row.path for row in rows)
        ):
            return "native_correlated", next(iter(writers))
        return "unknown", None

    def report(self):
        return {
            "source": "windows_kernel_etw_replay_prototype",
            "generation": self.generation,
            "complete": self._finished and not self.issues,
            "qualified": False,
            "automatic_termination": False,
            "loss_notifications": self.loss_notifications,
            "issues": list(self.issues),
            "writes": [asdict(row) for row in self.writes()],
        }
