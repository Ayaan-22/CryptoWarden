import ctypes
import os

import psutil

from src.config import PROTECTED_PROCESS_NAMES, RESPONSE_MODE, normalize_process_name
from src.utils.logger import logger
from src.utils.process_tools import kill_process

class Responder:
    def __init__(self):
        self.alerted_processes = set() # Track processes we've already shown popups for
        self._own_pid = os.getpid()

    def take_action(self, pid, process_name, reason):
        actual_name = self._resolve_process_name(pid, process_name)
        logger.critical(f"RANSOMWARE DETECTED! PID: {pid} ({actual_name})")
        logger.critical(f"Reason: {reason}")

        if RESPONSE_MODE in {"alert_only", "dry_run"}:
            logger.warning(f"Response mode is {RESPONSE_MODE}; no process was terminated.")
            self._show_alert_once(actual_name, reason)
            return

        if pid == self._own_pid or normalize_process_name(actual_name) in PROTECTED_PROCESS_NAMES:
            logger.error(f"Refusing to terminate protected process {pid} ({actual_name}).")
            self._show_alert_once(actual_name, reason)
            return
        
        # Kill Process
        if kill_process(pid):
            logger.info(f"Successfully terminated malicious process {pid}")
            self._show_alert_once(actual_name, reason)
        else:
            logger.error(f"FAILED TO TERMINATE PROCESS {pid}!")

    def _resolve_process_name(self, pid, fallback):
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            return fallback or "Unknown"

    def _show_alert_once(self, process_name, reason):
        if process_name in self.alerted_processes:
            return
        self.alerted_processes.add(process_name)
        self._show_alert(process_name, reason)

    def _show_alert(self, process_name, reason):
        # Run in a separate thread so we don't block the detection engine
        import threading
        def _alert():
            try:
                ctypes.windll.user32.MessageBoxW(0, f"Ransomware blocked: {process_name}\nReason: {reason}", "Security Alert", 0x10)
            except:
                pass
        
        threading.Thread(target=_alert, daemon=True).start()
