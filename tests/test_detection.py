"""
Unit tests for the CryptoWarden Detection Engine.
Tests all heuristic rules and scoring thresholds.
"""
import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from src.analysis.process_tracker import ProcessState
from src.detection.engine import DetectionEngine


@pytest.fixture
def engine():
    return DetectionEngine()


@pytest.fixture
def clean_process():
    """A normal process with no suspicious activity."""
    return ProcessState(pid=1000, name="notepad.exe")


@pytest.fixture
def rapid_modifier():
    """A process with rapid file modification (>5 in 10s window)."""
    ps = ProcessState(pid=2000, name="malware.exe")
    now = time.time()
    for i in range(10):
        ps.add_modification(now + i * 0.1)
    return ps


@pytest.fixture
def high_io_process():
    """A process with extreme IO write rate."""
    ps = ProcessState(pid=3000, name="ransomware.exe")
    ps.io_write_rate = 100.0
    return ps


@pytest.fixture
def renamer_process():
    """A process performing mass file renames."""
    ps = ProcessState(pid=4000, name="cryptor.exe")
    now = time.time()
    for i in range(5):
        ps.add_rename(now + i * 0.1)
    return ps


# ── Whitelist Tests ──

class TestWhitelist:
    def test_whitelisted_process_is_safe(self, engine):
        ps = ProcessState(pid=100, name="explorer.exe")
        ps.io_write_rate = 999  # Even with extreme IO
        is_mal, reason = engine.analyze_behavior(ps)
        assert is_mal is False
        assert reason == "Whitelisted"

    def test_svchost_is_whitelisted(self, engine):
        ps = ProcessState(pid=200, name="svchost.exe")
        is_mal, _ = engine.analyze_behavior(ps)
        assert is_mal is False


# ── Rule 1: Rapid Modification ──

class TestRapidModification:
    def test_normal_modification_rate_is_safe(self, engine, clean_process):
        clean_process.add_modification(time.time())
        is_mal, _ = engine.analyze_behavior(clean_process)
        assert is_mal is False

    def test_rapid_modifications_flagged(self, engine, rapid_modifier):
        """10 modifications should score +5, but alone isn't enough (need score >= 6 with 2+ reasons)."""
        is_mal, _ = engine.analyze_behavior(rapid_modifier)
        # Score is 5 with 1 reason, so threshold requires >=6 or 2+ reasons
        # This alone should NOT trigger (score 5 < 6)
        assert is_mal is False


# ── Rule 1.5: IO Write Rate ──

class TestIOWriteRate:
    def test_extreme_io_rate_triggers_detection(self, engine, high_io_process):
        """IO rate >50 gives score +10, which is >= 10, triggers even with 1 reason."""
        is_mal, reason = engine.analyze_behavior(high_io_process)
        assert is_mal is True
        assert "IO Write Rate" in reason

    def test_moderate_io_rate_alone_not_enough(self, engine):
        ps = ProcessState(pid=500, name="app.exe")
        ps.io_write_rate = 8.0  # Suspicious but not extreme (+3)
        is_mal, _ = engine.analyze_behavior(ps)
        assert is_mal is False

    def test_moderate_io_plus_modifications_triggers(self, engine):
        ps = ProcessState(pid=600, name="app.exe")
        ps.io_write_rate = 8.0  # +3
        now = time.time()
        for i in range(10):
            ps.add_modification(now + i * 0.1)  # +5
        # Total score = 8, 2 reasons -> should trigger
        is_mal, reason = engine.analyze_behavior(ps)
        assert is_mal is True


# ── Rule 2: High Entropy ──

class TestHighEntropy:
    def test_high_entropy_alone_not_enough(self, engine, clean_process):
        """Entropy score +4, only 1 reason, score < 6."""
        is_mal, _ = engine.analyze_behavior(clean_process, current_file_entropy=7.9)
        assert is_mal is False

    def test_high_entropy_plus_io_triggers(self, engine):
        ps = ProcessState(pid=700, name="virus.exe")
        ps.io_write_rate = 8.0  # +3
        # +4 for entropy => score 7, 2 reasons
        is_mal, reason = engine.analyze_behavior(ps, current_file_entropy=7.9)
        assert is_mal is True
        assert "Entropy" in reason


# ── Rule 3: Mass Renaming ──

class TestMassRenaming:
    def test_mass_renaming_triggers(self, engine, renamer_process):
        """5 renames gives +6, score >= 6 but only 1 reason."""
        renamer_process.io_write_rate = 8.0  # Add another reason +3
        is_mal, reason = engine.analyze_behavior(renamer_process)
        assert is_mal is True
        assert "Renaming" in reason


# ── Rule 4: Suspicious Extensions ──

class TestSuspiciousExtension:
    def test_suspicious_extension_triggers(self, engine, clean_process):
        """Extension score +8, which is >= 6 and >= 10? No, 8 < 10, 1 reason."""
        # Score 8, 1 reason -> needs len(reasons) >= 2 or score >= 10
        # So this alone should NOT trigger
        is_mal, _ = engine.analyze_behavior(clean_process, target_path="file.enc")
        assert is_mal is False

    def test_suspicious_extension_plus_io_triggers(self, engine):
        ps = ProcessState(pid=800, name="locker.exe")
        ps.io_write_rate = 8.0  # +3
        # +8 for extension => score 11, 2 reasons
        is_mal, reason = engine.analyze_behavior(ps, target_path="document.cryptolocker")
        assert is_mal is True
        assert "Extension" in reason


# ── Rule 5: Honey Pot / Canary ──

class TestHoneyPot:
    def test_canary_access_triggers(self, engine, clean_process):
        """Canary access gives +10, which is >= 10 -> triggers even alone."""
        is_mal, reason = engine.analyze_behavior(clean_process, is_honey_pot=True)
        assert is_mal is True
        assert "Canary" in reason


# ── Combined Scenarios ──

class TestCombinedAttack:
    def test_full_ransomware_behavior(self, engine):
        """Simulate a full ransomware attack with all indicators."""
        ps = ProcessState(pid=9999, name="lockbit.exe")
        ps.io_write_rate = 200.0
        now = time.time()
        for i in range(20):
            ps.add_modification(now + i * 0.05)
        for i in range(5):
            ps.add_rename(now + i * 0.05)

        is_mal, reason = engine.analyze_behavior(
            ps,
            current_file_entropy=7.95,
            is_honey_pot=True,
            target_path="file.enc"
        )
        assert is_mal is True
        # Should have multiple reasons
        assert "&" in reason

    def test_benign_high_io_whitelisted(self, engine):
        """Even extreme behavior is safe if whitelisted."""
        ps = ProcessState(pid=1, name="svchost.exe")
        ps.io_write_rate = 500.0
        is_mal, _ = engine.analyze_behavior(ps, current_file_entropy=7.9, is_honey_pot=True)
        assert is_mal is False
