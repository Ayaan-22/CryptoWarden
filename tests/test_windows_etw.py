import ctypes as ct
import os
from uuid import UUID

import pytest

from src.monitoring.windows_etw import (
    EVENT_TRACE,
    FILE,
    LOST_EVENT,
    PROCESS,
    THREAD,
    ClassicEvent,
    EventHeader,
    EventRecord,
    LogfileHeader,
    TraceLogfile,
    decode_record,
    replay_etl,
)


def record(provider, opcode, timestamp=1, version=2, flags=0x140):
    value = EventRecord()
    ct.memmove(ct.byref(value.header.provider), UUID(provider).bytes_le, 16)
    value.header.flags = flags
    value.header.descriptor.version = version
    value.header.descriptor.opcode = opcode
    value.header.timestamp = timestamp
    # Header actor deliberately disagrees with payload: it must never be used.
    value.header.process_id = 999
    value.header.thread_id = 998
    return value


def properties(**values):
    def get_property(record, name):
        value = values[name]
        if isinstance(value, bytes):
            return value
        width = 8 if name in {"UniqueProcessKey", "FileObject", "TTID"} else 4
        return value.to_bytes(width, "little")

    return get_property


def test_x64_windows_abi_layout():
    if ct.sizeof(ct.c_void_p) != 8:
        pytest.skip("x64-only native adapter")
    assert ct.sizeof(EventHeader) == 80
    assert ct.sizeof(EventRecord) == 112
    assert ct.sizeof(ClassicEvent) == 88
    assert ct.sizeof(LogfileHeader) == 280
    assert ct.sizeof(TraceLogfile) == 448
    assert TraceLogfile.header.offset == 120
    assert TraceLogfile.event_callback.offset == 424
    assert LogfileHeader.events_lost.offset == 48
    assert LogfileHeader.buffers_lost.offset == 276


@pytest.mark.parametrize(
    "provider,opcode,fields,kind",
    [
        (PROCESS, 1, {"ProcessId": 10, "UniqueProcessKey": 100}, "process_start"),
        (PROCESS, 2, {"ProcessId": 10, "UniqueProcessKey": 100}, "process_end"),
        (THREAD, 1, {"ProcessId": 10, "TThreadId": 11}, "thread_start"),
        (THREAD, 2, {"ProcessId": 10, "TThreadId": 11}, "thread_end"),
        (FILE, 65, {"FileObject": 500}, "file_invalidate"),
        (FILE, 66, {"FileObject": 500}, "file_close"),
        (FILE, 67, {"FileObject": 500}, "read"),
        (FILE, 68, {"FileObject": 500, "TTID": 11, "IoSize": 4096}, "write"),
        (FILE, 69, {"FileObject": 500}, "file_invalidate"),
        (FILE, 70, {"FileObject": 500}, "file_invalidate"),
        (FILE, 71, {"FileObject": 500}, "file_invalidate"),
    ],
)
def test_documented_classic_kernel_fields(provider, opcode, fields, kind):
    event = decode_record(ct.pointer(record(provider, opcode)), properties(**fields), "generation")
    assert event.kind == kind
    assert event.pid != 999 and event.tid != 998


def test_create_path_is_decoded_as_native_utf16_without_dos_path_guessing():
    path = r"\Device\HarddiskVolume3\日本語.txt"
    fields = properties(FileObject=500, OpenPath=(path + "\0").encode("utf-16-le"))
    event = decode_record(ct.pointer(record(FILE, 64)), fields, "generation")
    assert event.path == path and event.file_object == 500


@pytest.mark.parametrize("raw", [b"x", b"aa", b"\0\0", b"a\0\0\0b\0\0\0"])
def test_invalid_path_fails_closed(raw):
    with pytest.raises(ValueError):
        decode_record(
            ct.pointer(record(FILE, 64)), properties(FileObject=500, OpenPath=raw), "generation"
        )


@pytest.mark.parametrize("version,flags", [(1, 0x140), (3, 0x140), (2, 0x120), (2, 0x40)])
def test_unsupported_schema_or_architecture_does_not_guess_offsets(version, flags):
    with pytest.raises(ValueError, match="Unsupported"):
        decode_record(ct.pointer(record(FILE, 68, version=version, flags=flags)), None, "g")


def test_bad_field_width_and_missing_property_are_not_replaced_by_header_actor():
    value = ct.pointer(record(FILE, 68))
    with pytest.raises(ValueError, match="field width"):
        decode_record(value, properties(FileObject=b"\x01"), "g")
    with pytest.raises(KeyError):
        decode_record(value, properties(FileObject=500, IoSize=4096), "g")


@pytest.mark.parametrize("provider,opcode", [(PROCESS, 3), (THREAD, 4), (FILE, 36)])
def test_rundown_does_not_establish_observed_start(provider, opcode):
    assert decode_record(ct.pointer(record(provider, opcode)), None, "g") is None


@pytest.mark.parametrize("provider", [PROCESS, THREAD, FILE])
def test_unknown_kernel_operation_cannot_silently_preserve_stale_lifetimes(provider):
    with pytest.raises(ValueError, match="Unsupported kernel event opcode"):
        decode_record(ct.pointer(record(provider, 255)), None, "g")


@pytest.mark.parametrize(
    "provider,opcode", [(LOST_EVENT, 0), (EVENT_TRACE, 32), (EVENT_TRACE, 33), (EVENT_TRACE, 34)]
)
def test_native_loss_notifications_are_not_ignored(provider, opcode):
    with pytest.raises(ValueError, match="lost-event"):
        decode_record(ct.pointer(record(provider, opcode)), None, "g")


class ReplayApi:
    """Native ABI seam: exercise callback lifetime, final counters and close behavior."""

    def __init__(self, *, failure=None):
        self.failure = failure
        self.closed = []
        self.property = self.get_property
        self.values = {}

    def open(self, logfile):
        self.logfile = ct.cast(logfile, ct.POINTER(TraceLogfile))
        self.logfile.contents.header.pointer_size = 8
        self.logfile.contents.header.end_time = 100
        if self.failure == "unfinalized":
            self.logfile.contents.header.end_time = 0
        if self.failure == "circular":
            self.logfile.contents.header.log_mode = 2
        if self.failure == "32bit":
            self.logfile.contents.header.pointer_size = 4
        assert self.logfile.contents.mode == 0x10001000
        assert self.logfile.contents.logger is None
        return 123

    def get_property(self, value, name):
        return properties(**self.values)(value, name)

    def process(self, handles, count, start, end):
        callback_type = ct.WINFUNCTYPE if os.name == "nt" else ct.CFUNCTYPE
        callback = callback_type(None, ct.POINTER(EventRecord))(
            self.logfile.contents.event_callback
        )
        events = [
            (PROCESS, 1, {"ProcessId": 10, "UniqueProcessKey": 100}),
            (THREAD, 1, {"ProcessId": 10, "TThreadId": 11}),
            (FILE, 64, {"FileObject": 500, "OpenPath": "C:\\file.txt\0".encode("utf-16-le")}),
            (FILE, 68, {"FileObject": 500, "TTID": 11, "IoSize": 4096}),
        ]
        for timestamp, (provider, opcode, fields) in enumerate(events, 1):
            self.values = fields
            if self.failure == "decode" and opcode == 68:
                self.values = {}
            callback(ct.pointer(record(provider, opcode, timestamp)))
        # Loss may only become visible after the write has been processed.
        if self.failure == "events_lost":
            self.logfile.contents.header.events_lost = 3
        if self.failure == "buffers_lost":
            self.logfile.contents.header.buffers_lost = 2
        if self.failure == "consumer_loss":
            self.logfile.contents.events_lost = 1
        if self.failure == "buffer_callback_loss":
            local = TraceLogfile()
            local.header.events_lost = 1
            callback = callback_type(ct.c_uint32, ct.POINTER(TraceLogfile))(
                self.logfile.contents.buffer_callback
            )
            assert callback(ct.pointer(local)) == 1
        if self.failure == "exception":
            raise OSError("ProcessTrace exception")
        return 5 if self.failure == "process" else 0

    def close(self, handle):
        self.closed.append(handle)
        return 5 if self.failure == "close" else 0


def test_native_api_callbacks_produce_final_unqualified_evidence(tmp_path):
    api = ReplayApi()
    report = replay_etl(tmp_path / "fixture.etl", _api=api)
    assert api.closed == [123]
    assert report["complete"] is True and report["qualified"] is False
    assert report["writes"][0]["writer"]["pid"] == 10
    assert report["writes"][0]["status"] == "native_correlated"


@pytest.mark.parametrize(
    "failure",
    [
        "events_lost",
        "buffers_lost",
        "consumer_loss",
        "buffer_callback_loss",
        "decode",
        "process",
        "close",
        "unfinalized",
        "circular",
        "32bit",
    ],
)
def test_native_failure_revokes_all_attribution_and_closes_handle(tmp_path, failure):
    api = ReplayApi(failure=failure)
    report = replay_etl(tmp_path / "fixture.etl", _api=api)
    assert api.closed == [123]
    assert report["complete"] is False and report["issues"]
    assert all(row["writer"] is None and row["status"] == "unknown" for row in report["writes"])


def test_process_trace_exception_still_closes_handle(tmp_path):
    api = ReplayApi(failure="exception")
    with pytest.raises(OSError, match="ProcessTrace exception"):
        replay_etl(tmp_path / "fixture.etl", _api=api)
    assert api.closed == [123]


def test_native_open_trace_missing_etl_fails_without_evidence(tmp_path):
    if os.name != "nt" or ct.sizeof(ct.c_void_p) != 8:
        pytest.skip("Windows native API smoke test")
    with pytest.raises(OSError, match="OpenTraceW"):
        replay_etl(tmp_path / "does-not-exist.etl")
