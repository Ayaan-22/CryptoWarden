# 🛡️ CryptoWarden v2.1 - Early-Stage Ransomware Behavior Detection & Prevention System

CryptoWarden is a sophisticated, behavior-driven security solution designed to detect and neutralize ransomware attacks in their infancy. Unlike traditional antivirus software that relies on static signatures, CryptoWarden monitors real-time system behavior, identifying malicious patterns such as rapid file encryption, mass renaming, and unauthorized access to trap files.

![CryptoWarden Dashboard](https://raw.githubusercontent.com/Ayaan-22/CryptoWarden/main/assets/dashboard_mockup.png) *(Placeholder for dashboard screenshot)*

## 🚀 Overview

In the modern threat landscape, ransomware evolves faster than signature databases can update. CryptoWarden addresses this by focusing on the **behavioral indicators of compromise (BIOC)**. By combining multi-threaded file monitoring with probabilistic process attribution and entropy analysis, it provides a robust defense layer against zero-day ransomware threats.

## ✨ Key Features

- **High-Performance Async Engine**: Built on Python's `asyncio`, ensuring non-blocking monitoring and near-instantaneous response times.
- **Multi-Vector Detection**:
  - **Entropy Analysis**: Detects the transition from plain-text to high-entropy encrypted data.
  - **I/O Burst Detection**: Identifies processes performing unusually high numbers of file operations.
  - **Mass Renaming/Modification**: Flags processes that modify many files in a short time window.
- **Honey Pot (Canary File) System**: Automatically deploys hidden "tripwire" files. Any unauthorized interaction with these files triggers an immediate termination of the offending process.
- **Probabilistic Process Attribution**: Uses advanced I/O tracking to attribute file system events to specific processes even when direct PID acquisition is delayed or obscured.
- **Interactive Security Dashboard**: A real-time WebSocket-powered interface for monitoring system health, viewing live alerts, and manually managing whitelists/terminations.
- **Smart Whitelisting**: Pre-configured support for common system processes and developer tools to minimize false positives.

---

## 🏗️ System Architecture

CryptoWarden follows a modular, layer-based architecture for maximum scalability and maintainability.

### 1. Monitoring Layer (`src/monitoring/`)

- **`FileMonitor`**: Utilizes `watchdog` to hook into kernel-level file system events (Create, Modify, Move, Delete).
- **`ProcessMonitor`**: Periodically audits running processes and their I/O statistics using `psutil`.
- **`HoneyPot`**: Manages the deployment and monitoring of hidden canary files.

### 2. Analysis Layer (`src/analysis/`)

- **`ProcessTracker`**: Maintains a rolling history of behavior for every active process, tracking operation counts and types.
- **`EntropyCalculator`**: Performs Shannon Entropy calculations on modified files to detect encryption signatures.
- **`ProcessCache`**: A high-speed lookup table for mapping file handles to process IDs, optimizing performance.

### 3. Detection Engine (`src/detection/`)

- **Heuristic Logic**: Evaluates the cumulative "Risk Score" of a process based on:
  - Exceeding modification rate thresholds.
  - Producing high-entropy output files.
  - Triggering honey pot alerts.
  - Accessing sensitive directories sequentially.

### 4. Response Layer (`src/response/`)

- **`Responder`**: Executes mitigation strategies, primarily the forced termination of malicious process trees.
- **`DashboardBridge`**: Manages the WebSocket connection to the external UI, streaming alerts and receiving manual commands.

---

## 📂 Project Structure

```text
CryptoWarden/
├── config.yaml              # Central configuration (thresholds, paths, whitelist)
├── requirements.txt         # Project dependencies
├── dashboard/               # Interactive Security Dashboard
│   ├── index.html           # Dashboard entry point (open in browser)
│   ├── dashboard.css        # Stylesheet with design system
│   └── dashboard.js         # Client-side logic, charts, WebSocket
├── src/
│   ├── main.py              # Application entry point & Async orchestrator
│   ├── config.py            # Configuration loader and environment handler
│   ├── monitoring/          # FS and Process monitoring modules
│   ├── analysis/            # Behavioral and Entropy analysis logic
│   ├── detection/           # The Heuristic Detection Engine
│   ├── response/            # Mitigation and Dashboard communication
│   └── utils/               # Logger (with rotation), Process tools, Bridge
├── tests/
│   ├── ransomware_simulator.py  # Safe tool to simulate ransomware behavior
│   ├── test_detection.py    # Unit tests for the Detection Engine
│   ├── test_entropy.py      # Unit tests for Entropy calculations
│   └── mock_dashboard.py    # Mock server for testing dashboard integration
├── tools/
│   └── cleanup_honeypots.py # Remove canary files after testing
└── system.log               # Rotating log (5MB max, 3 backups)
```

---

## 🛠️ Installation & Setup

### Prerequisites

- **Windows OS (Optimized for Windows file system events)**
- **Python 3.10+**

### Installation

1. **Clone the Repository**:

```bash
git clone https://github.com/Ayaan-22/CryptoWarden.git
cd CryptoWarden
```

2. **Install Dependencies**:

```bash
pip install -r requirements.txt
```

3. **Configure the System**:
Edit `config.yaml` to specify which directories you want to protect and tune the detection sensitivity.

---

## 🎮 Usage & Commands

### Running the Core System

To start the protection engine and the dashboard bridge:

```bash
python src/main.py start
```

### Accessing the Dashboard

Once the system is running, simply open the interactive dashboard in your browser:

1. **Open `dashboard/index.html`** in any modern web browser (Chrome, Edge, etc.).
2. **The connection badge** in the top right will turn green once it connects to the running engine.
3. **Use the Overview, Activity Log, and Threats tabs** to navigate between views.

### Running Unit Tests

```bash
python -m pytest tests/ -v
```

### Cleaning Up Canary Files

After testing, remove the hidden honey pot files from monitored directories:

```bash
python tools/cleanup_honeypots.py
```

### Running the Ransomware Simulator (Testing)

To validate the detection engine, you can run the included simulator. **Warning**: This will create and "encrypt" files in a temporary directory (`RansomwareTestArea`) to test if CryptoWarden can stop it.

```bash
python tests/ransomware_simulator.py
```

### Running the Mock Dashboard

If you want to test the WebSocket integration without the full UI:

```bash
python tests/mock_dashboard.py
```

---

## ⚙️ Configuration (`config.yaml`)

The system is highly tunable via `config.yaml`. Key parameters include:

- **`monitoring.directories`**: List of paths to watch (supports environment variables like `%USERPROFILE%`).
- **`detection.max_modifications_per_sec`**: Threshold for rapid file changes before flagging.
- **`detection.max_entropy_threshold`**: Entropy level (0-8) that indicates encrypted/compressed data (Default: ~7.5).
- **`whitelist.processes`**: List of trusted process names that will be ignored by the engine.

---

## 🛡️ Mitigation Logic

When a process is flagged as malicious:

1. **Immediate Termination**: The engine attempts to kill the process and its child processes.
2. **Alerting**: A critical alert is sent to the Dashboard and logged to `system.log`.
3. **Snapshot**: The state of the process (behavioral data) is preserved for forensic analysis.

---

## ⚖️ Disclaimer

*This project is intended for educational and security research purposes only. While CryptoWarden is designed to provide a layer of protection, it should not be the sole defense mechanism for critical data. The authors are not responsible for any data loss or system damage caused by the use or misuse of this software.*

---
**Developed by [Ayaan-22](https://github.com/Ayaan-22)** | [Project Repository](https://github.com/Ayaan-22/CryptoWarden)
