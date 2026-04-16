import logging
import sys
import os
from datetime import datetime

def setup_logger(name="RansomwareGuard", log_file="system.log"):
    """
    Sets up a logger that writes to both console and file.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter(
        '%(asctime)s - [%(levelname)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    # File Handler
    try:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except PermissionError:
        print(f"Warning: Could not write to log file {log_file}")
        
    return logger

logger = setup_logger()
