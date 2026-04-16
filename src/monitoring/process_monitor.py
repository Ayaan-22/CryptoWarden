import time
import psutil
import threading
from src.utils.logger import logger
from src.config import WHITELISTED_PROCESSES

class ProcessMonitor:
    def __init__(self, process_tracker):
        self.tracker = process_tracker
        self.running = False
        self.thread = None
        self._previous_io = {} # pid -> (write_count, timestamp)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Process IO Monitor started.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

    def _monitor_loop(self):
        while self.running:
            try:
                # Iterate over all processes
                for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        io = proc.info['io_counters']
                        
                        if not io:
                            continue
                            
                        # Calculate Delta
                        current_writes = io.write_count
                        now = time.time()
                        
                        if pid in self._previous_io:
                            prev_writes, prev_time = self._previous_io[pid]
                            delta_writes = current_writes - prev_writes
                            time_diff = now - prev_time
                            
                            if time_diff > 0:
                                write_rate = delta_writes / time_diff
                                
                                # Update Tracker if significant activity
                                if write_rate > 2: # More than 2 writes/sec
                                    logger.debug(f"High IO: {name} ({pid}) - {write_rate:.2f} writes/s")
                                    proc_state = self.tracker.get_or_create(pid, name)
                                    proc_state.update_io_stats(write_rate)
                        
                        self._previous_io[pid] = (current_writes, now)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                time.sleep(1) # Poll every second
            except Exception as e:
                logger.error(f"Error in Process Monitor: {e}")
                time.sleep(1)
