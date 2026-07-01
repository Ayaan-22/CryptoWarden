import asyncio
import time
import sys
import os
import argparse
import signal

# --- Path Hardening for Cross-Device Compatibility ---
# Ensures 'src' can be found regardless of where the script is executed from
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from src.monitoring.file_monitor import FileMonitor
from src.monitoring.process_monitor import ProcessMonitor
from src.monitoring.honey_pot import setup_honey_pots, is_honey_pot_access
from src.analysis.process_tracker import ProcessTracker
from src.analysis.entropy import calculate_file_entropy
from src.detection.engine import DetectionEngine
from src.response.responder import Responder
from src.utils.logger import logger
from src.utils.process_tools import process_cache
from src.config import (
    DASHBOARD_AUTH_TOKEN,
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    add_whitelisted_process,
    is_whitelisted_process,
)

from src.utils.dashboard_bridge import DashboardBridge

class CryptoWarden:
    def __init__(self):
        self.tracker = ProcessTracker()
        self.detector = DetectionEngine()
        self.responder = Responder()
        self.process_monitor = ProcessMonitor(self.tracker)
        self.bridge = DashboardBridge(
            host=DASHBOARD_HOST,
            port=DASHBOARD_PORT,
            auth_token=DASHBOARD_AUTH_TOKEN
        )
        process_cache.tracker = self.tracker
        self.queue = asyncio.Queue()
        self.honey_pot_paths = set()
        self.running = False
        self.file_monitor = None
        self.self_pid = os.getpid()
        self.alerted_processes = set()
        self.stats = {"scanned": 0, "blocked": 0}

    async def handle_detection(self, pid, process_name, reason):
        alert_key = (pid, process_name)
        if alert_key in self.alerted_processes:
            return

        self.alerted_processes.add(alert_key)
        self.stats["blocked"] += 1
        await self.bridge.send_alert(pid, process_name, reason)

        if isinstance(pid, int) and pid > 0 and not is_whitelisted_process(process_name):
            self.responder.take_action(pid, process_name, reason)
            return

        logger.critical(f"RANSOMWARE-LIKE ACTIVITY DETECTED! PID: {pid} ({process_name})")
        logger.critical(f"Reason: {reason}")
        logger.warning("No process was terminated because the activity could not be safely mapped to a killable process.")

    async def publish_stats(self):
        while self.running:
            await self.bridge.send_stats(self.stats)
            await asyncio.sleep(1)

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
                try:
                    await self.bridge.send_activity(event)
                except Exception as e:
                    logger.debug(f"Could not update dashboard: {e}")

                if self.stats["scanned"] % 25 == 0:
                    logger.info(
                        f"Processed {self.stats['scanned']} file events "
                        f"({self.stats['blocked']} blocked so far)"
                    )

                if not pid or pid == -1:
                    top_procs = self.tracker.get_top_io_processes(limit=3)
                    attributed = False
                    for tpid, trate in top_procs:
                        if not isinstance(tpid, int) or tpid <= 0 or trate <= 0:
                            continue
                        tname = self.tracker.get_process_name(tpid)
                        if tname and tname != "Unknown" and not is_whitelisted_process(tname):
                            pid = tpid
                            pname = tname
                            logger.info(f"Probabilistically attributed {event_type} to high-IO process {pname} ({pid})")
                            attributed = True
                            break
                    if not attributed:
                        pid = -1
                        pname = "Unknown process"

                if pid == self.self_pid:
                    logger.debug(f"Ignoring self-attributed {event_type} event on {src_path}")
                    self.queue.task_done()
                    continue

                target_path = src_path # Default
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
                is_malicious, reason = self.detector.analyze_behavior(
                    proc_state, 
                    current_file_entropy=current_entropy, 
                    is_honey_pot=is_honey,
                    target_path=target_path if event_type in ['modified', 'created', 'moved'] else None
                )

                # 5. Respond
                if is_malicious:
                    await self.handle_detection(pid, pname, reason)
                
                # 6. Periodic Stats Update
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
                if pid == self.self_pid:
                    continue

                is_malicious, reason = self.detector.analyze_behavior(state, target_path=None)
                if is_malicious:
                    await self.handle_detection(pid, state.name, reason)
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
                        add_whitelisted_process(name)
                        await self.bridge.send_activity({"type": "info", "message": f"Whitelisted {name}"})

                self.bridge.command_queue.task_done()
            except Exception as e:
                logger.error(f"Error processing dashboard command: {e}")

    async def start(self):
        self.running = True
        logger.info("Initializing CryptoWarden Upgraded Detection System...")
        
        # Setup Signal Handlers
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop = asyncio.get_running_loop()
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
            except NotImplementedError:
                # signal.add_signal_handler not implemented on Windows for some loops
                pass
        
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
        self.stats_task = asyncio.create_task(self.publish_stats())
        
        logger.info("System fully operational. Monitoring for ransomware behavior...")
        
        try:
            while self.running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self):
        if not self.running:
            return

        self.running = False
        logger.info("Stopping system...")
        if self.file_monitor:
            self.file_monitor.stop()
        await self.process_monitor.stop()
        await self.bridge.stop()
        process_cache.stop()

        tasks = [
            getattr(self, "event_task", None),
            getattr(self, "check_task", None),
            getattr(self, "command_task", None),
            getattr(self, "stats_task", None),
        ]
        for task in tasks:
            if task:
                task.cancel()
        await asyncio.gather(*(task for task in tasks if task), return_exceptions=True)

def print_banner():
    banner = r"""
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

    if args.command != 'start':
        parser.print_help()
        return

    app = CryptoWarden()
    try:
        asyncio.run(app.start())
    except KeyboardInterrupt:
        logger.info("Interrupt received, shutdown requested.")
    finally:
        logger.info("Engine stopped. Goodbye.")

if __name__ == "__main__":
    main()
