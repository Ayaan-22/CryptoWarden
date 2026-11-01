import time

import pytest

from src.analysis.process_tracker import ProcessState, ProcessTracker
from src.detection.engine import DetectionEngine


@pytest.mark.parametrize("name", ["archive.exe", "explorer.exe", "python.exe", "svchost.exe"])
def test_single_archive_and_io_cannot_trigger(name):
    state = ProcessState(12, name)
    state.update_io_stats(999999, 99999999)
    result = DetectionEngine().evaluate(state, 7.99, target_path="ordinary.zip")
    assert not result.detected


@pytest.mark.parametrize("name", ["app.exe", "explorer.exe", "System"])
def test_canary_detection_is_visible_for_every_name(name):
    result = DetectionEngine().evaluate(ProcessState(12, name), is_honey_pot=True)
    assert result.detected and result.severity == "critical"


def test_suspicious_multi_file_sequence_triggers():
    state = ProcessState(-1, "Unresolved actor")
    for index in range(6):
        state.add_rename(path=f"document-{index}.enc")
    result = DetectionEngine().evaluate(state, 7.9, target_path="document-5.enc")
    assert result.detected
    assert any("Renaming" in signal for signal in result.signals)


def test_duplicate_path_notifications_are_not_mass_renames():
    state = ProcessState(123, "app.exe")
    for _ in range(100):
        state.add_rename(path="one-file.enc")
    assert not DetectionEngine().evaluate(state, 7.9, target_path="one-file.enc").detected


def test_real_rate_and_idle_expiry():
    clock = [100.0]
    state = ProcessState(123, "app.exe", clock=lambda: clock[0])
    for index in range(6):
        state.add_modification(path=f"file-{index}")
    assert state.get_modification_rate() == 0.6
    state.update_io_stats(100)
    clock[0] += 61
    assert state.get_modification_rate() == 0
    assert state.io_write_rate == 0


def test_out_of_order_event_clock_is_not_trusted():
    clock = [100.0]
    state = ProcessState(1, "app", clock=lambda: clock[0])
    state.add_modification(timestamp=time.time() + 999999, path="one")
    clock[0] += 11
    assert state.get_modification_rate() == 0


def test_process_lifetime_replaces_state():
    tracker = ProcessTracker()
    old = tracker.get_or_create(123, "app.exe", 100)
    old.update_io_stats(999)
    new = tracker.get_or_create(123, "app.exe", 200)
    assert old is not new and new.io_write_rate == 0


def test_tracker_expires_exited_process():
    tracker = ProcessTracker()
    tracker.get_or_create(123, "app", 1)
    tracker.expire(set())
    assert tracker.processes == {}


def test_rename_without_corroboration_does_not_trigger():
    state = ProcessState(-1, "Unknown")
    for index in range(5):
        state.add_rename(path=f"normal-{index}.txt")
    assert not DetectionEngine().evaluate(state, target_path="normal.txt").detected


def test_high_entropy_mass_rename_is_detected_without_known_suffix():
    state = ProcessState(-1, "Unknown")
    for index in range(8):
        state.add_rename(path=f"doc-{index}.data")
    assert DetectionEngine().evaluate(state, 7.9, target_path="doc-7.data").detected
