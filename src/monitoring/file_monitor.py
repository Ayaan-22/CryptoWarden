import time
import os
import asyncio
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.utils.logger import logger
from src.utils.process_tools import (
    get_process_using_file,
    get_recent_writer_candidate,
)
from src.config import (
    IGNORED_DIRECTORIES,
    IGNORED_EXTENSIONS,
    MONITOR_DIRECTORIES,
    SUSPICIOUS_EXTENSIONS,
)

class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, queue, loop):
        self.queue = queue
        self.loop = loop
        self._suspicious_rename_logs = 0

    def _process_event(self, event_type, src_path, dest_path=None):
        if self._has_ignored_extension(src_path):
            return

        if self._is_ignored_path(src_path) or (dest_path and self._is_ignored_path(dest_path)):
            return

        pid, pname = get_process_using_file(src_path, allow_direct_lookup=False)
        if event_type == 'moved' and dest_path and not pid:
            pid, pname = get_process_using_file(dest_path, allow_direct_lookup=False)

        attribution_confidence = "direct" if pid else "unknown"
        suspicious_extension = self._get_extension(dest_path) if event_type == 'moved' and dest_path else ""

        if suspicious_extension in SUSPICIOUS_EXTENSIONS:
            if not pid:
                pid, pname = get_recent_writer_candidate()
                attribution_confidence = "recent_writer" if pid else "unknown"

            if self._suspicious_rename_logs < 5:
                actor = f"{pname} ({pid})" if pid else "unknown process"
                logger.warning(f"Suspicious extension rename observed: {src_path} -> {dest_path} by {actor}")
                self._suspicious_rename_logs += 1

        event_data = {
            'type': event_type,
            'src_path': src_path,
            'dest_path': dest_path,
            'pid': pid,
            'process_name': pname,
            'timestamp': time.time(),
            'attribution_confidence': attribution_confidence,
            'suspicious_extension': suspicious_extension
        }
        
        # Use call_soon_threadsafe to put the event in the queue from the watchdog thread
        self.loop.call_soon_threadsafe(self.queue.put_nowait, event_data)

    def _has_ignored_extension(self, path):
        return self._get_extension(path) in IGNORED_EXTENSIONS

    def _get_extension(self, path):
        if not path:
            return ""
        _, ext = os.path.splitext(path)
        return ext.lower()

    def _is_ignored_path(self, path):
        path_parts = os.path.normpath(path).split(os.sep)
        normalized_ignored = {part.casefold() for part in IGNORED_DIRECTORIES}
        return any(part.casefold() in normalized_ignored for part in path_parts)

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event('modified', event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._process_event('created', event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._process_event('deleted', event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process_event('moved', event.src_path, event.dest_path)

class FileMonitor:
    def __init__(self, queue, loop):
        self.observer = Observer()
        self.handler = RansomwareEventHandler(queue, loop)
        self.watch_list = []

    def start(self):
        logger.info("Starting File Monitor...")
        for folder in MONITOR_DIRECTORIES:
            if not os.path.exists(folder):
                try:
                    os.makedirs(folder)
                except Exception:
                    continue
            
            abs_folder = os.path.abspath(folder)
            watch = self.observer.schedule(self.handler, abs_folder, recursive=True)
            self.watch_list.append(watch)
            logger.info(f"Monitoring directory: {abs_folder}")
        
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
