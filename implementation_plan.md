# Implementation Plan - CryptoWarden Audit & Issue Resolution

This plan details the findings of the complete project audit and outlines the steps to resolve the detection issues for the `@RansomwareTestArea` simulator.

## User Review Required

> [!IMPORTANT]
> The original design of CryptoWarden included **Probabilistic Process Attribution** to map file operations to the highest-IO non-whitelisted process when direct PID lookup missed. 
> However, because extreme IO rate alone previously triggered a ransomware alert, this caused false positives (e.g., terminating `WhatsApp.Root.exe` when it was writing to its own database while some random file event occurred in the workspace).
> To prevent these false positives, the developer disabled probabilistic attribution entirely. However, this broke the simulator detection because file operations are too fast for `psutil.open_files()` to capture, leading to all events being attributed to PID `-1` ("Unknown process"), which is never killed.
>
> We propose to:
> 1. Restore the probabilistic process attribution to allow simulator (and real ransomware) blocking.
> 2. Ensure safety by adding strict directory filtering to ignore noise from developer tools (like `.git`, `.pytest_cache`, `__pycache__`, etc.) from being monitored or analyzed.
> 3. Optimize the `ProcessCache` lookup to check the top IO processes first and avoid querying `open_files()` on whitelisted or inactive processes, reducing lookup time from **37 seconds to milliseconds**.

## Open Questions

None. The proposed architectural changes are clean and preserve the existing logic of the detection engine.

---

## Proposed Changes

### Core System Configuration & main Orchestrator

#### [MODIFY] [config.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Early-Stage%20Ransomware%20Behavior%20Detection%20&%20Prevention%20System/CryptoWarden/src/config.py)
- Ensure that the whitelist checks are robust and case-insensitive.
- Add helper/utility functions if needed for directory ignores.

#### [MODIFY] [main.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Early-Stage%20Ransomware%20Behavior%20Detection%20&%20Prevention%20System/CryptoWarden/src/main.py)
- Pass `DASHBOARD_HOST` and `DASHBOARD_PORT` to `DashboardBridge` during initialization.
- Connect the `ProcessTracker` instance to the `process_cache` so the cache can prioritize active high-IO processes for direct file PID lookups.
- Restore the **Probabilistic Process Attribution** logic to attribute unattributed file operations to the top non-whitelisted IO process, enabling real-time blocking of rapid ransomware payloads.

---

### Process Utilities & Performance Optimizations

#### [MODIFY] [process_tools.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Early-Stage%20Ransomware%20Behavior%20Detection%20&%20Prevention%20System/CryptoWarden/src/utils/process_tools.py)
- Optimize the `ProcessCache._refresh_loop` to skip whitelisted processes and only call `proc.open_files()` on processes that have actually written data (`io_counters.write_count`) since the last loop iteration.
- Optimize `ProcessCache._direct_lookup` to check the top active IO PIDs first (queried from the tracker) before doing a full process scan.
- Ensure that a full process scan only calls `open_files()` on non-whitelisted processes with a history of writing.

---

### Monitoring & Event Handling

#### [MODIFY] [file_monitor.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Early-Stage%20Ransomware%20Behavior%20Detection%20&%20Prevention%20System/CryptoWarden/src/monitoring/file_monitor.py)
- Add directory filtering to `_process_event` to ignore events occurring inside system or developer metadata directories (e.g., `.git`, `.pytest_cache`, `__pycache__`, `.venv`, `.agents`, `.gemini`). This prevents noise from background builds or test runs from leaking into process statistics and causing false-positive attributions.

---

## Verification Plan

### Automated Tests
We will run the existing pytest suite to ensure that all heuristic models, scoring thresholds, and whitelist logic pass:
```bash
pytest
```

### Manual Verification
1. Start the CryptoWarden daemon in the background:
   ```bash
   python src/main.py start
   ```
2. Run the ransomware simulator:
   ```bash
   python tests/ransomware_simulator.py
   ```
3. Verify in `system.log` and simulator console output that:
   - The simulator process (`python.exe`) is detected and successfully terminated.
   - The simulator does not finish executing and gets blocked.
