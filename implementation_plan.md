# Implementation Plan - CryptoWarden Upgrade

Upgrade CryptoWarden from a basic CLI POC to a robust, high-performance, and visually impressive security tool. This involves migrating to an asynchronous architecture, optimizing performance bottlenecks, and adding a premium real-time monitoring dashboard.

## User Review Required

> [!IMPORTANT]
> The upgrade involves a significant architectural change (migrating to `asyncio`). This will require a Python 3.7+ environment.
> The new Dashboard will be a web-based interface built using the StitchMCP framework.

## Proposed Changes

### Core Architecture & Optimization

#### [MODIFY] [main.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Early-Stage%20Ransomware%20Behavior%20Detection%20&%20Prevention%20System/CryptoWarden/src/main.py)
- Refactor to use `asyncio`.
- Implement an async event loop that handles file events, process monitoring, and UI updates.
- Decouple the detector from the monitor using an `asyncio.Queue`.

#### [MODIFY] [process_tools.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Early-Stage%20Ransomware%20Behavior%20Detection%20&%20Prevention%20System/CryptoWarden/src/utils/process_tools.py)
- Implement a `ProcessCache` to reduce the overhead of `get_process_using_file`. 
- Instead of full iteration on every event, we will poll open files for all processes every 5 seconds and maintain a lookup table.

#### [NEW] [honey_pot.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Early-Stage%20Ransomware%20Behavior%20Detection%20&%20Prevention%20System/CryptoWarden/src/monitoring/honey_pot.py)
- Implement a "Canary File" system. Hidden files with attractive names (e.g., `_passwords.txt`) are placed in monitored directories. Any modification to these files results in an immediate high suspicion score.

### Dashboard & UI (StitchMCP)

#### [NEW] CryptoWarden Dashboard
- Create a modern, dark-themed dashboard using StitchMCP.
- **Screen 1: Overview**: Real-time charts of system I/O, monitoring status, and "System Health" meter.
- **Screen 2: Activity Log**: A live stream of file system events with PID attribution.
- **Screen 3: Alerts**: A high-priority view for malicious process detection with "Kill" and "Whitelist" actions.

### Configuration & Tooling

#### [NEW] [config.yaml](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Early-Stage%20Ransomware%20Behavior%20Detection%20&%20Prevention%20System/CryptoWarden/config.yaml)
- Move hardcoded configurations from `src/config.py` to a YAML file for easier user customization.

## Verification Plan

### Automated Tests
- Run `tests/ransomware_simulator.py` to verify that the detection still works and triggers the response.
- Verify that the Dashboard receives real-time updates via a bridge (e.g., a simple WebSocket or shared state).

### Manual Verification
- Manually edit a file in a monitored directory and check if it appears in the Dashboard.
- Trigger a "Canary File" modification and verify immediate detection.
