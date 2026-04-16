import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.utils.logger import logger
from src.utils.process_tools import get_process_using_file
from src.config import MONITOR_DIRECTORIES, IGNORED_EXTENSIONS

class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, callback_function):
        """
        callback_function: function to call when a relevant event occurs.
        Signature: callback(event_type, src_path, dest_path, pid, process_name)
        """
        self.callback = callback_function

    def _process_event(self, event_type, src_path, dest_path=None):
        if src_path.endswith(tuple(IGNORED_EXTENSIONS)):
            return

        # Attempt to find the PID responsible. 
        # Note: On 'created' or 'modified', the file might still be open.
        # On 'deleted', checking who *had* it open is hard without kernel drivers.
        # We try our best effort immediately.
        
        pid, pname = None, None
        
        # Strategy: If Modified, check who has it open.
        if event_type in ['modified', 'created']:
            pid, pname = get_process_using_file(src_path)
            
        # Strategy: If Renamed, check the NEW path
        if event_type == 'moved' and dest_path:
            pid, pname = get_process_using_file(dest_path)

        # Log and Callback
        # logger.debug(f"Event: {event_type} | File: {src_path} | PID: {pid}")
        
        self.callback({
            'type': event_type,
            'src_path': src_path,
            'dest_path': dest_path,
            'pid': pid,
            'process_name': pname,
            'timestamp': time.time()
        })

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
    def __init__(self, analysis_callback):
        self.observer = Observer()
        self.handler = RansomwareEventHandler(analysis_callback)
        self.watch_list = []

    def start(self):
        logger.info("Starting File Monitor...")
        for folder in MONITOR_DIRECTORIES:
            if not os.path.exists(folder):
                try:
                    os.makedirs(folder)
                except Exception:
                    continue
            
            # Recursive monitoring
            watch = self.observer.schedule(self.handler, folder, recursive=True)
            self.watch_list.append(watch)
            logger.info(f"Monitoring directory: {folder}")
        
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
