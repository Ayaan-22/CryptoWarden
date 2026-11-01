"""Bounded file-event intake. Watchdog supplies paths, not authenticated writer PIDs."""

import os
import queue as thread_queue
import threading
import time
from collections import deque
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import EventDispatcher, EventQueue

from src.config import config, normalize_path
from src.monitoring.honey_pot import safe_root


class LossAwareEventQueue(EventQueue):
    """Bound watchdog's upstream emitter queue without blocking shutdown on a full buffer."""

    def __init__(self, capacity, on_loss):
        super().__init__(maxsize=capacity)
        self.on_loss = on_loss

    def put(self, item, block=True, timeout=None):
        try:
            super().put(item, block=False)
        except thread_queue.Full:
            self.on_loss(1)
            if item is EventDispatcher.stop_event:
                try:
                    self.get_nowait()
                    self.task_done()
                    super().put(item, block=False)
                except (thread_queue.Empty, thread_queue.Full):
                    pass


class BoundedObserver(Observer):
    """Override the public event_queue property; tested against locked watchdog 6.0."""

    def __init__(self, capacity, on_loss):
        self.bounded_queue = LossAwareEventQueue(capacity, on_loss)
        super().__init__()

    @property
    def event_queue(self):
        return self.bounded_queue


class EventInbox:
    """Bound the watchdog-to-loop handoff, including scheduled callback count."""

    def __init__(self, queue, loop, capacity, on_loss=None):
        self.queue, self.loop, self.capacity = queue, loop, capacity
        self.on_loss = on_loss or (lambda count: None)
        self.pending = deque()
        self.lock = threading.Lock()
        self.scheduled = False
        self.closed = False
        self.dropped = 0

    def offer(self, event):
        with self.lock:
            if self.closed:
                return
            if len(self.pending) >= self.capacity:
                # Prefer a canary to ordinary traffic, but never pretend overflow did not happen.
                if event.get("is_canary"):
                    self.pending.pop()
                else:
                    self.dropped += 1
                    return
                self.dropped += 1
            if event.get("is_canary"):
                self.pending.appendleft(event)
            else:
                self.pending.append(event)
            if not self.scheduled:
                self.scheduled = True
                self.loop.call_soon_threadsafe(self._drain)

    def mark_loss(self, count):
        with self.lock:
            if self.closed:
                return
            self.dropped += count
            if not self.scheduled:
                self.scheduled = True
                self.loop.call_soon_threadsafe(self._drain)

    def _drain(self):
        with self.lock:
            dropped, self.dropped = self.dropped, 0
            batch = [self.pending.popleft() for _ in range(min(64, len(self.pending)))]
            self.scheduled = False
        if dropped:
            self.on_loss(dropped)
        for event in batch:
            try:
                self.queue.put_nowait(event)
            except Exception as error:
                import asyncio

                if not isinstance(error, asyncio.QueueFull):
                    raise
                self.on_loss(1)
        with self.lock:
            if self.pending and not self.scheduled and not self.closed:
                self.scheduled = True
                self.loop.call_soon(self._drain)

    def close(self, on_discard=None):
        with self.lock:
            self.closed = True
            pending = len(self.pending)
            dropped = self.dropped
            self.pending.clear()
            self.dropped = 0
        if dropped:
            self.on_loss(dropped)
        if pending:
            (on_discard or self.on_loss)(pending)


class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, queue, loop, settings=None, canaries=(), on_loss=None, excluded_roots=()):
        self.settings = settings or config
        self.canaries = set(canaries)
        self.excluded_roots = tuple(normalize_path(p) for p in excluded_roots)
        self.inbox = EventInbox(queue, loop, self.settings["monitoring"]["queue_capacity"], on_loss)

    def _is_ignored_path(self, path):
        parts = Path(normalize_path(path)).parts
        if any(
            part.casefold()
            in {x.casefold() for x in self.settings["monitoring"]["ignored_directories"]}
            for part in parts
        ):
            return True
        normalized = normalize_path(path)
        return any(
            normalized == root or normalized.startswith(root + os.sep)
            for root in self.excluded_roots
        )

    def _has_ignored_extension(self, path):
        return Path(path).suffix.casefold() in self.settings["monitoring"]["ignored_extensions"]

    def _process_event(self, event_type, src_path, dest_path=None, is_directory=False):
        src = normalize_path(src_path)
        dest = normalize_path(dest_path) if dest_path else None
        is_canary = src in self.canaries or dest in self.canaries
        suspicious = bool(
            dest
            and Path(dest).suffix.casefold() in self.settings["detection"]["suspicious_extensions"]
        )
        if not is_canary:
            if event_type == "moved":
                if self._is_ignored_path(src) and (not dest or self._is_ignored_path(dest)):
                    return
                if (
                    self._has_ignored_extension(src)
                    and (not dest or self._has_ignored_extension(dest))
                    and not suspicious
                ):
                    return
            elif self._is_ignored_path(src) or self._has_ignored_extension(src):
                return
        self.inbox.offer(
            {
                "type": event_type,
                "src_path": src,
                "dest_path": dest,
                "timestamp": time.time(),
                "received_monotonic": time.monotonic(),
                "is_directory": is_directory,
                "is_canary": is_canary,
                "pid": None,
                "process_name": None,
                "process": None,
                "source": "watchdog",
                "attribution_confidence": "unknown",
            }
        )

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._process_event("created", event.src_path)

    def on_deleted(self, event):
        self._process_event("deleted", event.src_path, is_directory=event.is_directory)

    def on_moved(self, event):
        self._process_event("moved", event.src_path, event.dest_path, event.is_directory)


class FileMonitor:
    def __init__(self, queue, loop, settings=None, canaries=(), on_loss=None, on_discard=None):
        self.settings = settings or config
        self.on_discard = on_discard
        self.handler = RansomwareEventHandler(
            queue, loop, self.settings, canaries, on_loss, [self.settings["storage"]["directory"]]
        )
        self.observer = BoundedObserver(
            self.settings["monitoring"]["queue_capacity"], self.handler.inbox.mark_loss
        )
        self.watch_list = []
        self.health = "stopped"

    def start(self):
        try:
            for folder in self.settings["monitoring"]["directories"]:
                if not safe_root(folder):
                    raise ValueError(f"Protected directory missing or unsafe: {folder}")
                self.watch_list.append(self.observer.schedule(self.handler, folder, recursive=True))
            if not self.watch_list:
                raise ValueError("No protected directories")
            self.observer.start()
            self.health = "running"
        except BaseException:
            if self.observer.is_alive():
                self.observer.stop()
                self.observer.join(timeout=5)
            self.health = "failed"
            raise

    def stop(self):
        self.handler.inbox.close(self.on_discard)
        self.observer.stop()
        if self.observer.is_alive():
            self.observer.join(timeout=5)
        self.health = "failed" if self.observer.is_alive() else "stopped"
