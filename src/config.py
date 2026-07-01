import os
from pathlib import Path

import yaml
from src.utils.logger import logger

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _deep_merge(defaults, overrides):
    for key, value in (overrides or {}).items():
        if isinstance(defaults.get(key), dict) and isinstance(value, dict):
            _deep_merge(defaults[key], value)
        else:
            defaults[key] = value
    return defaults


def _normalize_extension(ext):
    ext = str(ext or "").strip().lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    return ext

def load_config():
    config_path = Path(os.environ.get("CRYPTOWARDEN_CONFIG", PROJECT_ROOT / "config.yaml"))
    default_config = {
        'monitoring': {
            'directories': [os.path.join(os.path.expanduser("~"), "Documents")],
            'ignored_extensions': ['.tmp', '.log'],
            'ignored_directories': ['.git', '.pytest_cache', '__pycache__', '.venv', '.agents', '.gemini']
        },
        'detection': {
            'max_modifications_per_sec': 5,
            'max_entropy_threshold': 7.5,
            'min_file_size_for_entropy': 1024,
            'entropy_check_samples': 5,
            'suspicious_extensions': ['.enc', '.crypt', '.locked', '.wannacry', '.odin', '.zepto', '.locky', '.aes', '.cryptolocker']
        },
        'whitelist': {
            'processes': ['explorer.exe', 'svchost.exe', 'codex.exe']
        },
        'response': {
            'mode': 'terminate',
            'protected_processes': ['System', 'Registry', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe']
        },
        'dashboard': {
            'host': '127.0.0.1',
            'port': 8001,
            'auth_token': ''
        }
    }

    if not os.path.exists(config_path):
        logger.warning(f"Config file {config_path} not found. Using defaults.")
        return default_config

    try:
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f) or {}
            _deep_merge(default_config, user_config)
    except Exception as e:
        logger.error(f"Error loading config: {e}. Using defaults.")

    # Expand environment variables in directories
    processed_dirs = []
    for d in default_config['monitoring']['directories']:
        processed_dirs.append(os.path.expandvars(d))
    default_config['monitoring']['directories'] = processed_dirs

    return default_config

# Load global config
config = load_config()

MONITOR_DIRECTORIES = config['monitoring']['directories']
IGNORED_EXTENSIONS = {
    _normalize_extension(ext)
    for ext in config['monitoring'].get('ignored_extensions', [])
}
IGNORED_DIRECTORIES = set(config['monitoring'].get('ignored_directories', []))
MAX_FILE_MODIFICATIONS_PER_SEC = config['detection']['max_modifications_per_sec']
MAX_ENTROPY_THRESHOLD = config['detection']['max_entropy_threshold']
MIN_FILE_SIZE_FOR_ENTROPY = config['detection']['min_file_size_for_entropy']
ENTROPY_CHECK_SAMPLES = config['detection']['entropy_check_samples']
SUSPICIOUS_EXTENSIONS = {
    _normalize_extension(ext)
    for ext in config['detection'].get('suspicious_extensions', [])
}

def normalize_process_name(process_name):
    return (process_name or "").casefold()

WHITELISTED_PROCESSES = {
    normalize_process_name(process_name)
    for process_name in config['whitelist']['processes']
}

def is_whitelisted_process(process_name):
    return normalize_process_name(process_name) in WHITELISTED_PROCESSES

def add_whitelisted_process(process_name):
    WHITELISTED_PROCESSES.add(normalize_process_name(process_name))

PROTECTED_PROCESS_NAMES = {
    normalize_process_name(process_name)
    for process_name in config.get('response', {}).get('protected_processes', [])
}
RESPONSE_MODE = config.get('response', {}).get('mode', 'terminate')
DASHBOARD_HOST = config['dashboard']['host']
DASHBOARD_PORT = config['dashboard']['port']
DASHBOARD_AUTH_TOKEN = config['dashboard'].get('auth_token', '')
