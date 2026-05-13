from src.config import (
    MAX_FILE_MODIFICATIONS_PER_SEC, 
    MAX_ENTROPY_THRESHOLD,
    WHITELISTED_PROCESSES
)
from src.utils.logger import logger

class DetectionEngine:
    def __init__(self):
        pass

    def analyze_behavior(self, process_state, current_file_entropy=0.0, is_honey_pot=False, target_path=None):
        """
        Returns a tuple (is_ransomware: bool, reason: str)
        """
        if process_state.name in WHITELISTED_PROCESSES:
            return False, "Whitelisted"

        score = 0
        reasons = []

        # Rule 1: Rapid File Modification
        mod_rate = process_state.get_modification_rate()
        if mod_rate > MAX_FILE_MODIFICATIONS_PER_SEC:
            score += 5
            reasons.append(f"Rapid Modification ({mod_rate} files/10s)")

        # Rule 1.5: High IO Write Rate
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
            
        # Rule 3: Mass Renaming
        if len(process_state.renames) > 3:
            score += 6
            reasons.append(f"Rapid Renaming ({len(process_state.renames)} files/10s)")

        # Rule 4: Suspicious Extension Change
        if target_path:
            ext = target_path.split('.')[-1].lower()
            suspicious_exts = {'enc', 'crypt', 'locked', 'wannacry', 'odin', 'zepto', 'locky', 'aes', 'cryptolocker'}
            if ext in suspicious_exts:
                score += 8
                reasons.append(f"Suspicious Extension Change (.{ext})")

        # Rule 5: Honey-pot / Canary File Access
        if is_honey_pot:
            score += 10
            reasons.append("Canary File Modification Detected")

        # Decision
        if score >= 6:
            # Harder block if multiple factors exist
            if len(reasons) >= 2 or score >= 10:
                return True, " & ".join(reasons)
            
        return False, None
