import os
import yaml
from src.utils.logger import logger

def load_config():
    config_path = "config.yaml"
    default_config = {
        'monitoring': {
            'directories': [os.path.join(os.path.expanduser("~"), "Documents")],
            'ignored_extensions': ['.tmp', '.log']
        },
        'detection': {
            'max_modifications_per_sec': 5,
            'max_entropy_threshold': 7.5,
            'min_file_size_for_entropy': 1024,
            'entropy_check_samples': 5
        },
        'whitelist': {
            'processes': ['explorer.exe', 'svchost.exe']
        },
        'dashboard': {
            'host': '127.0.0.1',
            'port': 8001
        }
    }

    if not os.path.exists(config_path):
        logger.warning(f"Config file {config_path} not found. Using defaults.")
        return default_config

    try:
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f)
            # Deep merge simple dictionaries
            for key in user_config:
                if key in default_config and isinstance(default_config[key], dict):
                    default_config[key].update(user_config[key])
                else:
                    default_config[key] = user_config[key]
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
IGNORED_EXTENSIONS = set(config['monitoring']['ignored_extensions'])
MAX_FILE_MODIFICATIONS_PER_SEC = config['detection']['max_modifications_per_sec']
MAX_ENTROPY_THRESHOLD = config['detection']['max_entropy_threshold']
MIN_FILE_SIZE_FOR_ENTROPY = config['detection']['min_file_size_for_entropy']
ENTROPY_CHECK_SAMPLES = config['detection']['entropy_check_samples']
WHITELISTED_PROCESSES = set(config['whitelist']['processes'])
DASHBOARD_HOST = config['dashboard']['host']
DASHBOARD_PORT = config['dashboard']['port']
