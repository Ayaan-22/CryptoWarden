from src.config import (
    MAX_FILE_MODIFICATIONS_PER_SEC, 
    MAX_ENTROPY_THRESHOLD,
    SUSPICIOUS_EXTENSIONS,
    is_whitelisted_process
)
from src.utils.logger import logger

class DetectionEngine:
    def __init__(self):
        pass

    def analyze_behavior(self, process_state, current_file_entropy=0.0, is_honey_pot=False, target_path=None):
        """
        Returns a tuple (is_ransomware: bool, reason: str)
        """
        is_whitelisted = is_whitelisted_process(process_state.name)

        score = 0
        reasons = []
        suspicious_ext = None

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
            ext = "." + target_path.rsplit('.', 1)[-1].lower() if '.' in target_path else ''
            if ext in SUSPICIOUS_EXTENSIONS:
                suspicious_ext = ext
                score += 8
                reasons.append(f"Suspicious Extension Change ({ext})")

        # Rule 5: Honey-pot / Canary File Access
        if is_honey_pot:
            score += 10
            reasons.append("Canary File Modification Detected")

        if is_whitelisted:
            high_confidence_file_attack = (
                is_honey_pot
                or (
                    suspicious_ext
                    and (
                        len(process_state.renames) > 3
                        or current_file_entropy > MAX_ENTROPY_THRESHOLD
                    )
                )
            )

            if not high_confidence_file_attack:
                return False, "Whitelisted"

            reasons.insert(0, "Whitelisted process showed high-confidence ransomware behavior")

        # Decision
        if score >= 6:
            file_behavior_confirmed = (
                mod_rate > MAX_FILE_MODIFICATIONS_PER_SEC
                or len(process_state.renames) > 3
                or suspicious_ext
                or current_file_entropy > MAX_ENTROPY_THRESHOLD
                or is_honey_pot
            )

            # I/O rate alone is too noisy to terminate real desktop apps.
            if file_behavior_confirmed and (len(reasons) >= 2 or score >= 10):
                return True, " & ".join(reasons)
            
        return False, None
