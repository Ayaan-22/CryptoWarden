from src.utils.process_tools import kill_process
from src.utils.logger import logger
import ctypes

class Responder:
    def __init__(self):
        self.alerted_processes = set() # Track processes we've already shown popups for

    def take_action(self, pid, process_name, reason):
        logger.critical(f"RANSOMWARE DETECTED! PID: {pid} ({process_name})")
        logger.critical(f"Reason: {reason}")
        
        # Kill Process
        if kill_process(pid):
            logger.info(f"Successfully terminated malicious process {pid}")
            
            # Only show the popup once per process name to avoid alert storms
            if process_name not in self.alerted_processes:
                self.alerted_processes.add(process_name)
                self._show_alert(process_name, reason)
        else:
            logger.error(f"FAILED TO TERMINATE PROCESS {pid}!")

    def _show_alert(self, process_name, reason):
        # Run in a separate thread so we don't block the detection engine
        import threading
        def _alert():
            try:
                ctypes.windll.user32.MessageBoxW(0, f"Ransomware blocked: {process_name}\nReason: {reason}", "Security Alert", 0x10)
            except:
                pass
        
        threading.Thread(target=_alert, daemon=True).start()
