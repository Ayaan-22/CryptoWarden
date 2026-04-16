import psutil
import os
from src.utils.logger import logger

def get_process_using_file(filepath: str):
    """
    Attempts to find the process ID (pid) that has a specific file open.
    Returns (pid, name) or (None, None).
    WARNING: This is resource intensive.
    """
    filepath = os.path.normpath(filepath)
    try:
        # iterate over all processes
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                if not proc.info['open_files']:
                    continue
                
                for f in proc.info['open_files']:
                    if os.path.normpath(f.path) == filepath:
                        return proc.info['pid'], proc.info['name']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logger.error(f"Error checking processes for file {filepath}: {e}")
        
    return None, None

def kill_process(pid: int):
    """
    Terminates a process by PID.
    """
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=3)
        return True
    except Exception as e:
        logger.error(f"Failed to kill process {pid}: {e}")
        try:
            # Force kill
            proc.kill()
            return True
        except:
            return False
