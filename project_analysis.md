# Early-Stage Ransomware Behavior Detection & Prevention System

## Overview
This project is an early-stage, behavioral-based ransomware detection and prevention system written in Python. Instead of relying on static malware signatures, it actively monitors the system for anomalous behavior pattern typical of ransomware attacks, such as rapid file modifications, high I/O bulk writes, mass file renaming, and generating high-entropy files (resembling encrypted data).

## Project Architecture & Modules

The system is highly modularized under the `src/` directory and connected via the `main.py` entry point. 

### 1. Monitoring Layer (`src/monitoring`)
- **`file_monitor.py`**: Utilizes the `watchdog` library to implement real-time hooks on user directories (typically Documents, Desktop, Pictures). It tracks file system events (created, modified, deleted, moved/renamed). For modification and creation events, it attempts to attribute the change to a specific Process ID (PID) using the utility functions.
- **`process_monitor.py`**: A fallback/supplementary monitor using `psutil`. It polls all running processes periodically to capture abnormal IO write bursts. This is crucial because ransomware could potentially bypass `watchdog` hooks or mask its file handles.

### 2. Analysis & Tracking Layer (`src/analysis`)
- **`process_tracker.py`**: Acts as a state machine. It maintains a `ProcessState` for each active PID handling files. It tracks:
  - Timestamps of file modifications and renames (within sliding 10-second windows).
  - Entropy history of files written by this process.
  - Overall IO write rates.
- **`entropy.py`**: Contains algorithms to calculate the **Shannon Entropy** of file data. Because ransomware encrypts files (resulting in high-entropy randomness), the tool checks if generated files exceed the `MAX_ENTROPY_THRESHOLD` (approx > 7.5). To maintain system performance on large files, it performs sampled reads (first, middle, and last 1KB). 

### 3. Detection Engine (`src/detection`)
- **`engine.py`**: The brain of the operation. It evaluates the `ProcessState` against a set of heuristic rules to calculate a *suspicion score*:
  - **Rule 1**: Rapid file modification bursts (score +5).
  - **Rule 1.5**: Critical I/O write rate spikes (score +10 for extreme, +3 for high).
  - **Rule 2**: High entropy writes suggesting encryption (score +4).
  - **Rule 3**: Mass file extension renaming operations (score +6).
  > [!TIP]
  >  If the calculated score is `>= 6`, the process is flagged as **malicious**. The engine also cross-references against a whitelist (`svchost.exe`, `explorer.exe`) to prevent system-crashing false positives.

### 4. Response Mechanism (`src/response`)
- **`responder.py`**: Upon receiving a malicious verdict, it takes immediate mitigating action. It forcibly terminates the offending process using `psutil`, effectively halting the encryption process before it can spread further. It then natively alerts the user via a Windows MessageBox (`ctypes.windll.user32`).

### 5. Simulator (`tests/ransomware_simulator.py`)
- A multithreaded simulation script that safely creates dummy text documents in a `RansomwareTestArea` folder. It then mimics ransomware by rapidly overwriting them with random bytes (to mimic high entropy encryption) and renaming them to `.enc`. This is used to test the capabilities of the Detection Engine safely.

---

## Technical Assessment

### Strengths
- **Behavioral Approach**: Inherently superior to signature-based AV for zero-day ransomware.
- **Optimized Parsing**: Uses smart heuristics such as sampling large files for entropy rather than loading entire gigabytes into RAM.
- **Multi-vector Indicators**: Checks both File System APIs (`watchdog`) and Process I/O counters (`psutil`), preventing malware from easily evading detection by disguising only one behavior.

### Weaknesses & Limitations
- **User-Mode Tracing**: Attributing file events to processes via `psutil.process_iter` (`get_process_using_file`) in a user-mode script is extremely resource-intensive and prone to race conditions. A real-world commercial solution implements this via a **Kernel-mode File System Minifilter Driver** (in C/C++).
- **Latency Delay**: Python's garbage collection and global interpreter lock (GIL) might introduce micro-second latency blocks. Very fast ransomware (like LockBit) might successfully encrypt a substantial number of files before the heuristic score crosses the threshold and the process receives a termination signal.
- **Privilege Separation**: If the ransomware is running with `SYSTEM` privileges and the detector is in user-context, the `kill_process` signal will be met with `Access Denied`.

## Summary
This project acts as an excellent proof-of-concept (POC) demonstrating the behavioral indicators of modern crypto-malware and establishing a structured, automated pipeline for rapid detection and mitigation on Windows environments.
