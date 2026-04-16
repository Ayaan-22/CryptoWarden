import time
import sys
import threading
from src.monitoring.file_monitor import FileMonitor
from src.monitoring.process_monitor import ProcessMonitor
from src.analysis.process_tracker import ProcessTracker
from src.analysis.entropy import calculate_file_entropy
from src.detection.engine import DetectionEngine
from src.response.responder import Responder
from src.utils.logger import logger

tracker = ProcessTracker()
detector = DetectionEngine()
responder = Responder()
process_monitor = ProcessMonitor(tracker)

def event_callback(event):
    """
    Called by FileMonitor when an event occurs.
    """
    event_type = event['type']
    pid = event['pid']
    pname = event['process_name']
    src_path = event['src_path']
    timestamp = event['timestamp']

    if not pid:
        # If we couldn't map PID, we can't attribute blame (in this user-mode version)
        # However, for 'modified', we usually can.
        return

    # 1. Update Process State
    proc_state = tracker.update_access(pid, pname, event_type, timestamp)

    # 2. Additional Analysis (Entropy)
    current_entropy = 0.0
    if event_type in ['modified', 'created', 'moved']:
        # If renamed or modified, check entropy of the file
        # Check dest_path if moved, src_path otherwise
        target_path = event['dest_path'] if event_type == 'moved' else src_path
        current_entropy = calculate_file_entropy(target_path)
        if current_entropy > 0:
            proc_state.add_entropy_sample(current_entropy)

    # 3. Detect
    is_malicious, reason = detector.analyze_behavior(proc_state, current_entropy)

    # 4. Respond
    if is_malicious:
        responder.take_action(pid, pname, reason)

import argparse

def print_banner():
    banner = """
   ____      _               _       __               __         
  / ____/_  __/ /_  ___  ____  | |     / /___ __________/ /__  ____ 
 / /   / / / / __ \/ _ \/ __ \ | | /| / / __ `/ ___/ __  / _ \/ __ \ 
/ /___/ /_/ / /_/ /  __/ / / / | |/ |/ / /_/ / /  / /_/ /  __/ / / /
\____/\__, /_.___/\___/_/ /_/  |__/|__/\__,_/_/   \__,_/\___/_/ /_/ 
     /____/                                                         
    """
    print(banner)
    print("            CryptoWarden - Ransomware Behavior Detection & Prevention            ")
    print("="*81 + "\n")

def main():
    parser = argparse.ArgumentParser(description="CryptoWarden (CyberWarden) CLI Tool")
    parser.add_argument('command', choices=['start'], nargs='?', help='Command to execute (e.g. start)')
    
    args = parser.parse_args()

    print_banner()

    if args.command == 'start':
        logger.info("Initializing CryptoWarden Detection System...")
        
        process_monitor.start()
        monitor = FileMonitor(event_callback)
        monitor.start()
        
        try:
            while True:
                # We need to periodically check the tracker for Suspicious IO processes
                # because file_callback might not trigger for them if mapping failed.
                for pid, state in list(tracker.processes.items()):
                     is_malicious, reason = detector.analyze_behavior(state)
                     if is_malicious:
                         responder.take_action(pid, state.name, reason)
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping system...")
            monitor.stop()
            process_monitor.stop()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
