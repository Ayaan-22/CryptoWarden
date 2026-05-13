import logging
import sys
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

def setup_logger(name="RansomwareGuard", log_file="system.log"):
    """
    Sets up a logger that writes to both console and file.
    Uses RotatingFileHandler to prevent unbounded log growth.
    Max 5MB per file, keeps 3 backups (system.log.1, .2, .3).
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
    
    # Rotating File Handler — 5MB max, keep 3 backups
    try:
        fh = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding='utf-8'
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except PermissionError:
        print(f"Warning: Could not write to log file {log_file}")
        
    return logger

logger = setup_logger()
