"""Off-loop IO context sampling, keyed by process lifetime, including idle samples."""

import asyncio
import os
import time

import psutil

from src.config import normalize_path
from src.models import ProcessIdentity


class ProcessMonitor:
    def __init__(self, process_tracker, interval=1):
        self.tracker, self.interval = process_tracker, interval
        self._previous_io = {}
        self.task = None
        self.health = "stopped"
        self.last_sample = None
        self.instances = []

    def sample(self):
        now = time.monotonic()
        rows, active, instances = [], set(), []
        previous = {}
        for proc in psutil.process_iter(["pid", "name", "create_time", "exe", "io_counters"]):
            try:
                info = proc.info
                if info["pid"] == os.getpid() or info["create_time"] is None:
                    continue
                identity = ProcessIdentity(
                    info["pid"],
                    info["create_time"],
                    info["name"] or "Unknown",
                    normalize_path(info["exe"]) if info["exe"] else "",
                )
                key, io = (identity.pid, identity.create_time), info["io_counters"]
                active.add(key)
                if not io:
                    continue
                old = self._previous_io.get(key)
                rates = (0.0, 0.0)
                if old and now > old[2]:
                    rates = (
                        max(0, io.write_count - old[0]) / (now - old[2]),
                        max(0, io.write_bytes - old[1]) / (now - old[2]),
                    )
                previous[key] = (io.write_count, io.write_bytes, now)
                rows.append((identity, rates))
                if rates[0] > 0 or rates[1] > 0:
                    instances.append(
                        {
                            **identity.to_dict(),
                            "writes_per_second": round(rates[0], 2),
                            "bytes_per_second": round(rates[1], 2),
                        }
                    )
            except (psutil.Error, OSError, TypeError):
                continue
        self._previous_io = previous
        return (
            rows,
            active,
            sorted(instances, key=lambda row: row["bytes_per_second"], reverse=True)[:25],
        )

    async def _monitor_loop(self):
        while True:
            rows, active, self.instances = await asyncio.to_thread(self.sample)
            for identity, rates in rows:
                self.tracker.get_or_create(
                    identity.pid, identity.name, identity.create_time
                ).update_io_stats(*rates)
            self.tracker.expire(active)
            self.health, self.last_sample = "running", time.time()
            await asyncio.sleep(self.interval)

    async def start(self):
        self.task = asyncio.create_task(self._monitor_loop(), name="process-monitor")

    async def stop(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        self.health = "stopped"
