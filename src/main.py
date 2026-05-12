import asyncio
import time
import sys
import argparse
from src.monitoring.file_monitor import FileMonitor
from src.monitoring.process_monitor import ProcessMonitor
from src.monitoring.honey_pot import setup_honey_pots, is_honey_pot_access
from src.analysis.process_tracker import ProcessTracker
from src.analysis.entropy import calculate_file_entropy
from src.detection.engine import DetectionEngine
from src.response.responder import Responder
from src.utils.logger import logger
from src.utils.process_tools import process_cache

from src.utils.dashboard_bridge import DashboardBridge

class CryptoWarden:
    def __init__(self):
        self.tracker = ProcessTracker()
        self.detector = DetectionEngine()
        self.responder = Responder()
        self.process_monitor = ProcessMonitor(self.tracker)
        self.bridge = DashboardBridge()
        self.queue = asyncio.Queue()
        self.honey_pot_paths = set()
        self.running = False
        self.stats = {"scanned": 0, "blocked": 0}

    async def process_events(self):
        """
        Consumes events from the queue and performs detection.
        """
        while self.running:
            try:
                event = await self.queue.get()
                
                event_type = event['type']
                pid = event['pid']
                pname = event['process_name']
                src_path = event['src_path']
                timestamp = event['timestamp']

                # 0. Send to Dashboard
                self.stats["scanned"] += 1
                await self.bridge.send_activity(event)

                if not pid:
                    self.queue.task_done()
                    continue

                # 1. Check Honey-pot
                is_honey = is_honey_pot_access(src_path, self.honey_pot_paths)
                if event_type == 'moved' and event.get('dest_path'):
                    is_honey = is_honey or is_honey_pot_access(event['dest_path'], self.honey_pot_paths)

                # 2. Update Process State
                proc_state = self.tracker.update_access(pid, pname, event_type, timestamp)

                # 3. Entropy Analysis
                current_entropy = 0.0
                if event_type in ['modified', 'created', 'moved']:
                    target_path = event['dest_path'] if event_type == 'moved' else src_path
                    loop = asyncio.get_running_loop()
                    current_entropy = await loop.run_in_executor(None, calculate_file_entropy, target_path)
                    if current_entropy > 0:
                        proc_state.add_entropy_sample(current_entropy)

                # 4. Detect
                is_malicious, reason = self.detector.analyze_behavior(proc_state, current_entropy, is_honey)

                # 5. Respond
                if is_malicious:
                    self.stats["blocked"] += 1
                    await self.bridge.send_alert(pid, pname, reason)
                    self.responder.take_action(pid, pname, reason)
                
                # 6. Periodic Stats Update
                if self.stats["scanned"] % 10 == 0:
                    await self.bridge.send_stats(self.stats)

                self.queue.task_done()
            except Exception as e:
                logger.error(f"Error in event processor: {e}")

    async def background_checks(self):
        """
        Periodically checks all processes in the tracker for suspicious behavior
        that might have missed the file monitor.
        """
        while self.running:
            for pid, state in list(self.tracker.processes.items()):
                is_malicious, reason = self.detector.analyze_behavior(state)
                if is_malicious:
                    self.stats["blocked"] += 1
                    await self.bridge.send_alert(pid, state.name, reason)
                    self.responder.take_action(pid, state.name, reason)
            await asyncio.sleep(2)

    async def process_commands(self):
        """
        Listens for interactive commands from the dashboard.
        """
        while self.running:
            try:
                cmd = await self.bridge.command_queue.get()
                command = cmd.get("command")
                
                if command == "kill":
                    pid = cmd.get("pid")
                    if pid:
                        logger.info(f"Dashboard requested KILL for PID {pid}")
                        self.responder.take_action(pid, "Dashboard User", "Manual Termination Request")
                
                elif command == "whitelist":
                    name = cmd.get("process_name")
                    if name:
                        logger.info(f"Dashboard requested WHITELIST for {name}")
                        from src.config import WHITELISTED_PROCESSES
                        WHITELISTED_PROCESSES.add(name)
                        await self.bridge.send_activity({"type": "info", "message": f"Whitelisted {name}"})

                self.bridge.command_queue.task_done()
            except Exception as e:
                logger.error(f"Error processing dashboard command: {e}")

    async def start(self):
        self.running = True
        logger.info("Initializing CryptoWarden Upgraded Detection System...")
        
        # Start background services
        process_cache.start()
        self.honey_pot_paths = setup_honey_pots()
        
        # Start async monitors and bridge
        await self.bridge.start()
        await self.process_monitor.start()
        
        loop = asyncio.get_running_loop()
        self.file_monitor = FileMonitor(self.queue, loop)
        self.file_monitor.start()

        # Start tasks
        self.event_task = asyncio.create_task(self.process_events())
        self.check_task = asyncio.create_task(self.background_checks())
        self.command_task = asyncio.create_task(self.process_commands())
        
        logger.info("System fully operational. Monitoring for ransomware behavior...")
        
        try:
            while self.running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self):
        self.running = False
        logger.info("Stopping system...")
        self.file_monitor.stop()
        await self.process_monitor.stop()
        await self.bridge.stop()
        process_cache.stop()
        self.event_task.cancel()
        self.check_task.cancel()
        self.command_task.cancel()

def print_banner():
    banner = """
   ______                 __      _       __               __         
  / ____/______  ______  / /_____| |     / /___ __________/ /__  ____ 
 / /   / ___/ / / / __ \/ __/ __ \ | /| / / __ `/ ___/ __  / _ \/ __ \\
/ /___/ /  / /_/ / /_/ / /_/ /_/ / |/ |/ / /_/ / /  / /_/ /  __/ / / /
\____/_/   \__, / .___/\__/\____/|__/|__/\__,_/_/   \__,_/\___/_/ /_/ 
          /____/_/                                                    
    """
    print(banner)
    print("            CryptoWarden v2.0 - Advanced Ransomware Detection            ")
    print("="*81 + "\n")

def main():
    parser = argparse.ArgumentParser(description="CryptoWarden CLI Tool")
    parser.add_argument('command', choices=['start'], nargs='?', help='Command to execute (e.g. start)')
    
    args = parser.parse_args()

    print_banner()

    if args.command == 'start':
        try:
            app = CryptoWarden()
            asyncio.run(app.start())
        except KeyboardInterrupt:
            pass
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
