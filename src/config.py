import os

# System Configuration
MONITOR_DIRECTORIES = [
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Pictures"),
    # Add a dedicated test folder for safety
    os.path.join(os.path.expanduser("~"), "Desktop", "RansomwareTestArea")
]

# Ignored Extensions (System/Temp files)
IGNORED_EXTENSIONS = {'.tmp', '.log', '.ini', '.lnk', '.sys', '.dll'}

# Detection Thresholds
MAX_FILE_MODIFICATIONS_PER_SEC = 5
MAX_ENTROPY_THRESHOLD = 7.5  # Encrypted files usually > 7.8
MIN_FILE_SIZE_FOR_ENTROPY = 1024  # 1KB
ENTROPY_CHECK_SAMPLES = 5  # Number of suspicious files before triggering

# Whitelist (System Critical Processes)
WHITELISTED_PROCESSES = {
    'explorer.exe',
    'svchost.exe',
    'MsMpEng.exe',  # Windows Defender
    'csrss.exe',
    'System',
    'Antigravity.exe',
    'SearchIndexer.exe',
    'SupportAssistAgent.exe',
    'Dell.TechHub.exe'
}
