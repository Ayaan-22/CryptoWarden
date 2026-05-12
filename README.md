# CryptoWarden v2.0 - Early-Stage Ransomware Behavior Detection & Prevention System

CryptoWarden is a sophisticated, behavioral-based ransomware detection and prevention system. It goes beyond static signatures by monitoring real-time system behavior for patterns typical of ransomware attacks.

## New in v2.0 (The Upgrade)

The latest version introduces significant architectural and functional improvements:

### 1. High-Performance Asynchronous Architecture
The core engine has been refactored to use **Python AsyncIO**. This ensures that file monitoring, process analysis, and response mechanisms run concurrently without blocking, significantly reducing the detection-to-mitigation latency.

### 2. Optimized Process Attribution (ProcessCache)
To solve the bottleneck of mapping file events to processes, v2.0 implements a **background Process Cache**. It maintains a high-speed lookup table of open file handles, replacing expensive `psutil` iterations with O(1) dictionary lookups.

### 3. Honey-pot (Canary File) System
CryptoWarden now deploys **hidden canary files** in monitored directories. These files (e.g., `_passwords.txt`, `backup_keys.dat`) act as tripwires. Any interaction with these files by an unknown process triggers an immediate critical alert and mitigation response.

### 4. Real-Time Security Dashboard (Stitch UI)
A premium, dark-themed dashboard provides absolute visibility into system health:
- **Live Activity Feed**: Real-time stream of file system events with PID attribution.
- **Threat Intelligence**: Detailed analysis of suspicious processes with "Risk Level" and "Behavioral Indicators".
- **One-Click Mitigation**: Quickly kill or whitelist processes directly from the UI.

## Project Architecture

The system is modularized under the `src/` directory:

- **`monitoring/`**: Real-time file system hooks (`watchdog`) and IO burst detection (`psutil`). Now includes `honey_pot.py`.
- **`analysis/`**: Tracks process state, calculates file entropy, and maintains history.
- **`detection/`**: The heuristic engine that calculates suspicion scores based on rapid modifications, high entropy, mass renaming, and honey-pot triggers.
- **`response/`**: Forcibly terminates malicious processes and alerts the user.
- **`utils/`**: Includes the new `ProcessCache` and logging utilities.

## Getting Started

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start Monitoring**:
   ```bash
   python src/main.py start
   ```

3. **Run Simulator (Safety Test)**:
   ```bash
   python tests/ransomware_simulator.py
   ```

## Design Aesthetics

CryptoWarden v2.0 features a premium "Digital Fortress" design language:
- **Glassmorphism**: Translucent UI elements with backdrop blurs.
- **Cyber Palette**: Deep black background with neon green and cyber blue accents.
- **High Contrast**: Designed for mission-critical monitoring and rapid threat response.

---
*Disclaimer: This is a security research tool and should be used responsibly in a controlled environment.*
