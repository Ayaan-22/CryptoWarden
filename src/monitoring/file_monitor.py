import time
import os
import asyncio
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.utils.logger import logger
from src.utils.process_tools import get_process_using_file
from src.config import MONITOR_DIRECTORIES, IGNORED_EXTENSIONS

class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, queue, loop):
        self.queue = queue
        self.loop = loop

    def _process_event(self, event_type, src_path, dest_path=None):
        if src_path.endswith(tuple(IGNORED_EXTENSIONS)):
            return

        pid, pname = get_process_using_file(src_path)
        if event_type == 'moved' and dest_path and not pid:
            pid, pname = get_process_using_file(dest_path)

        event_data = {
            'type': event_type,
            'src_path': src_path,
            'dest_path': dest_path,
            'pid': pid,
            'process_name': pname,
            'timestamp': time.time()
        }
        
        # Use call_soon_threadsafe to put the event in the queue from the watchdog thread
        self.loop.call_soon_threadsafe(self.queue.put_nowait, event_data)

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
            
            watch = self.observer.schedule(self.handler, folder, recursive=True)
            self.watch_list.append(watch)
            logger.info(f"Monitoring directory: {folder}")
        
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
