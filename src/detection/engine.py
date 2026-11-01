"""Explainable multi-file heuristics; a detection never establishes writer identity."""

from pathlib import Path

from src.config import config
from src.models import DetectionResult


class DetectionEngine:
    def __init__(self, settings=None):
        self.settings = settings or config["detection"]

    def evaluate(
        self,
        state,
        current_file_entropy=None,
        is_honey_pot=False,
        target_path=None,
        entropy_delta=None,
    ):
        state.prune()
        d = self.settings
        modifications, renames = state.unique_modifications(), state.unique_renames()
        fanout = max(modifications, renames) >= d["min_unique_files"]
        rapid = state.get_modification_rate() >= d["max_modifications_per_sec"]
        mass_rename = renames >= d["rename_threshold"]
        suspicious = bool(
            target_path and Path(target_path).suffix.casefold() in d["suspicious_extensions"]
        )
        high_entropy = (
            current_file_entropy is not None and current_file_entropy > d["max_entropy_threshold"]
        )
        transition = high_entropy and entropy_delta is not None and entropy_delta >= 1.5
        signals, score = [], 0
        for matches, weight, text in [
            (is_honey_pot, 100, "Canary integrity event"),
            (rapid and fanout, 25, f"Rapid modification across {modifications} files"),
            (mass_rename, 35, f"Renaming across {renames} files"),
            (suspicious, 25, "Suspicious extension"),
            (high_entropy and fanout, 20, "High entropy across a multi-file sequence"),
            (transition and fanout, 20, "Observed entropy increase"),
        ]:
            if matches:
                score += weight
                signals.append(text)
        # IO is context only: common archive/database activity must not authorize detection.
        detected = is_honey_pot or (fanout and score >= 55) or (mass_rename and suspicious)
        severity = "critical" if is_honey_pot else "high" if detected else "medium"
        return DetectionResult(detected, min(score, 100), tuple(signals), severity)

    def analyze_behavior(
        self, process_state, current_file_entropy=0.0, is_honey_pot=False, target_path=None
    ):
        result = self.evaluate(process_state, current_file_entropy, is_honey_pot, target_path)
        return result.detected, result.reason or None
