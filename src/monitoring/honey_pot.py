import os
from src.utils.logger import logger
from src.config import MONITOR_DIRECTORIES

HONEY_POT_FILENAMES = [
    "_passwords.txt",
    "_confidential.docx",
    "backup_keys.dat",
    "private_keys.key"
]

def setup_honey_pots():
    """
    Creates hidden canary files in monitored directories.
    Returns a set of normalized absolute paths to these files.
    """
    honey_pot_paths = set()
    for directory in MONITOR_DIRECTORIES:
        if not os.path.exists(directory):
            continue
            
        for filename in HONEY_POT_FILENAMES:
            file_path = os.path.join(directory, filename)
            try:
                if not os.path.exists(file_path):
                    with open(file_path, "w") as f:
                        f.write("This is a system-generated canary file for ransomware detection. DO NOT DELETE.")
                
                # Hide the file on Windows
                if os.name == 'nt':
                    import ctypes
                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_HIDDEN)
                
                honey_pot_paths.add(os.path.normpath(file_path))
            except Exception as e:
                logger.error(f"Failed to create honey pot {file_path}: {e}")
                
    return honey_pot_paths

def is_honey_pot_access(filepath: str, honey_pot_paths: set):
    """
    Checks if a given filepath is one of the canary files.
    """
    return os.path.normpath(filepath) in honey_pot_paths
