from src.config import (
    MAX_FILE_MODIFICATIONS_PER_SEC, 
    MAX_ENTROPY_THRESHOLD,
    WHITELISTED_PROCESSES
)
from src.utils.logger import logger

class DetectionEngine:
    def __init__(self):
        pass

    def analyze_behavior(self, process_state, current_file_entropy=0.0):
        """
        Returns a tuple (is_ransomware: bool, reason: str)
        """
        if process_state.name in WHITELISTED_PROCESSES:
            return False, "Whitelisted"

        score = 0
        reasons = []

        # Rule 1: Rapid File Modification (From Watchdog mapping)
        mod_rate = process_state.get_modification_rate()
        if mod_rate > MAX_FILE_MODIFICATIONS_PER_SEC:
            score += 5
            reasons.append(f"Rapid Modification ({mod_rate} files/10s)")

        # Rule 1.5: High IO Write Rate (From Polling)
        if process_state.io_write_rate > 50: # Critical IO
            score += 10
            reasons.append(f"Extreme IO Write Rate ({process_state.io_write_rate:.2f} ops/s)")
        elif process_state.io_write_rate > 5: # Suspicious IO
            score += 3
            reasons.append(f"High IO Write Rate ({process_state.io_write_rate:.2f} ops/s)")

        # Rule 2: High Entropy Write (Encryption)
        if current_file_entropy > MAX_ENTROPY_THRESHOLD:
            score += 4
            reasons.append(f"High Entropy Write ({current_file_entropy:.2f})")
            
        # Rule 3: Mass Renaming (Encryption often renames .txt -> .enc)
        if len(process_state.renames) > 3:
            score += 6
            reasons.append(f"Rapid Renaming ({len(process_state.renames)} files/10s)")

        # Decision
        # If High Entropy AND Rapid Modification -> ALMOST CERTAINLY RANSOMWARE
        if score >= 6:
            return True, " & ".join(reasons)
            
        return False, None
