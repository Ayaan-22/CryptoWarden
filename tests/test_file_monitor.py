import queue

from src.monitoring import file_monitor
from src.monitoring.file_monitor import RansomwareEventHandler


class ImmediateLoop:
    def call_soon_threadsafe(self, callback, *args):
        callback(*args)


def test_metadata_directory_events_are_ignored():
    events = queue.Queue()
    handler = RansomwareEventHandler(events, ImmediateLoop())

    handler._process_event("created", r"C:\repo\.git\index")

    assert events.empty()


def test_suspicious_rename_uses_recent_writer_attribution(monkeypatch):
    events = queue.Queue()
    handler = RansomwareEventHandler(events, ImmediateLoop())

    monkeypatch.setattr(file_monitor, "get_process_using_file", lambda *_args, **_kwargs: (None, None))
    monkeypatch.setattr(file_monitor, "get_recent_writer_candidate", lambda: (1234, "locker.exe"))

    handler._process_event("moved", r"C:\data\doc.txt", r"C:\data\doc.txt.enc")

    event = events.get_nowait()
    assert event["pid"] == 1234
    assert event["process_name"] == "locker.exe"
    assert event["attribution_confidence"] == "recent_writer"
    assert event["suspicious_extension"] == ".enc"
