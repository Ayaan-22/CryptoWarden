from src.utils.process_tools import kill_process
from src.utils.logger import logger
import ctypes

class Responder:
    def __init__(self):
        pass

    def take_action(self, pid, process_name, reason):
        logger.critical(f"RANSOMWARE DETECTED! PID: {pid} ({process_name})")
        logger.critical(f"Reason: {reason}")
        
        # Kill Process
        if kill_process(pid):
            logger.info(f"Successfully terminated malicious process {pid}")
            self._show_alert(process_name, reason)
        else:
            logger.error(f"FAILED TO TERMINATE PROCESS {pid}!")

    def _show_alert(self, process_name, reason):
        # Initial attempt at a Windows Message Box
        try:
            ctypes.windll.user32.MessageBoxW(0, f"Ransomware blocked: {process_name}\nReason: {reason}", "Security Alert", 0x10)
        except:
            pass
