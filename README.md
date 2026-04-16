# CryptoWarden 🛡️

**CryptoWarden** is an early-stage, behavioral-based ransomware detection and prevention system written in Python.

Unlike traditional antivirus software that relies on static malware signatures, CryptoWarden actively monitors your system in real-time for the anomalous behavior patterns typical of zero-day crypto-malware.

## 🚀 Key Features

- **Behavioral Heuristics:** Detects rapid file modifications, mass extension renaming (e.g., appending `.enc`), and abnormal I/O write bursts.
- **Mathematical Entropy Analysis:** Analyzes files on the fly using Shannon Entropy to detect the high level of randomness characteristic of encrypted data.
- **Active Mitigation:** Automatically terminates malicious processes (`psutil.kill`) before they can encrypt the rest of your system.
- **Whitelist Protection:** Prevents catastrophic system failure by explicitly allowing core OS functions (like `svchost.exe` and `explorer.exe`).
- **Resource Optimized:** Efficiently samples large files for entropy calculations rather than loading entire multi-gigabyte files into memory.

## 📁 Project Structure

```
CryptoWarden/
│
├── src/
│   ├── config.py              # System configuration and thresholds
│   ├── main.py                # Entry point
│   ├── analysis/              # Entropy calculations and process tracking
│   ├── detection/             # Core decision engine for suspicion scoring
│   ├── monitoring/            # Watchdog file observers and process I/O polling
│   ├── response/              # Process termination and alerting
│   └── utils/                 # Logging and process/file mapping
│   
├── tests/
│   └── ransomware_simulator.py # Safe simulator to test the detection engine
│
├── requirements.txt           # Python dependencies
└── README.md
```

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/CryptoWarden.git
   cd CryptoWarden
   ```

2. **Install the dependencies:**
   It is recommended to run this inside a virtual environment.
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the system:**
   Review `src/config.py` to add or remove directories you wish to monitor or adjust the detection thresholds.

4. **Run the tool:**
   *Note: Administrative privileges might be required to trace and terminate certain processes.*
   ```bash
   python -m src.main
   ```

## ⚠️ Testing the System

A simulator script is provided to safely test the detection engine without harming your actual files.
1. Run `python -m src.main` in one terminal.
2. In a separate terminal, run `python tests/ransomware_simulator.py`. 
3. The simulator will create a `RansomwareTestArea` folder on your Desktop, generate dummy files, and violently "encrypt" them.
4. CryptoWarden should detect the behavior, flag the process, and terminate the simulator.

## 🛑 Disclaimer

This project is intended for **educational and research purposes only**. While it demonstrates effective behavioral indicators of modern ransomware, it is a user-mode Python application and should **not** replace enterprise security solutions (EDR/XDR) that utilize Kernel-level Minifilter drivers for absolute protection.
