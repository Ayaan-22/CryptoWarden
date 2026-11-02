"""Opt-in x64 Windows ETL consumer using OpenTrace/ProcessTrace and TDH.

No session is started, stopped or attached to; no driver or response integration.
Only classic kernel v2 process/thread/file events are decoded. Native callbacks
copy fields synchronously; no native pointer escapes the callback lifetime.
"""

import ctypes as ct
import os
from pathlib import Path
from uuid import UUID

from src.analysis.native_attribution import NativeAttribution, NativeEvent

U8, U16, U32, U64, I64 = ct.c_uint8, ct.c_uint16, ct.c_uint32, ct.c_uint64, ct.c_int64
PROCESS = "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"
THREAD = "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"
FILE = "90cbdc39-4a3e-11d1-84f4-0000f80464e3"
EVENT_TRACE = "68fdd900-4a3e-11d1-84f4-0000f80464e3"
LOST_EVENT = "6a399ae0-4bc6-4de9-870b-3657f8947e7e"


class GUID(ct.Structure):
    _fields_ = [("data1", U32), ("data2", U16), ("data3", U16), ("data4", U8 * 8)]


class EventDescriptor(ct.Structure):
    _fields_ = [
        ("id", U16),
        ("version", U8),
        ("channel", U8),
        ("level", U8),
        ("opcode", U8),
        ("task", U16),
        ("keyword", U64),
    ]


class EventHeader(ct.Structure):
    _fields_ = [
        ("size", U16),
        ("header_type", U16),
        ("flags", U16),
        ("event_property", U16),
        ("thread_id", U32),
        ("process_id", U32),
        ("timestamp", I64),
        ("provider", GUID),
        ("descriptor", EventDescriptor),
        ("processor_time", U64),
        ("activity", GUID),
    ]


class EventRecord(ct.Structure):
    _fields_ = [
        ("header", EventHeader),
        ("buffer_context", U32),
        ("extended_count", U16),
        ("data_length", U16),
        ("extended_data", ct.c_void_p),
        ("user_data", ct.c_void_p),
        ("context", ct.c_void_p),
    ]


class ClassicEvent(ct.Structure):
    _fields_ = [
        ("header", U64 * 6),  # EVENT_TRACE_HEADER, 48 bytes, alignment 8
        ("instance", U32),
        ("parent_instance", U32),
        ("parent_guid", GUID),
        ("mof_data", ct.c_void_p),
        ("mof_length", U32),
        ("client_context", U32),
    ]


class LogfileHeader(ct.Structure):
    _fields_ = [
        ("buffer_size", U32),
        ("version", U32),
        ("provider_version", U32),
        ("processors", U32),
        ("end_time", I64),
        ("timer_resolution", U32),
        ("max_file_size", U32),
        ("log_mode", U32),
        ("buffers_written", U32),
        ("start_buffers", U32),
        ("pointer_size", U32),
        ("events_lost", U32),
        ("cpu_speed", U32),
        ("logger_name", ct.c_void_p),
        ("logfile_name", ct.c_void_p),
        ("timezone", U16 * 86),  # TIME_ZONE_INFORMATION, 172 bytes
        ("boot_time", I64),
        ("perf_freq", I64),
        ("start_time", I64),
        ("reserved", U32),
        ("buffers_lost", U32),
    ]


class TraceLogfile(ct.Structure):
    _fields_ = [
        ("filename", ct.c_wchar_p),
        ("logger", ct.c_wchar_p),
        ("current_time", I64),
        ("buffers_read", U32),
        ("mode", U32),
        ("current_event", ClassicEvent),
        ("header", LogfileHeader),
        ("buffer_callback", ct.c_void_p),
        ("buffer_size", U32),
        ("filled", U32),
        ("events_lost", U32),
        ("event_callback", ct.c_void_p),
        ("kernel_trace", U32),
        ("context", ct.c_void_p),
    ]


class PropertyDescriptor(ct.Structure):
    _fields_ = [("name", U64), ("index", U32), ("reserved", U32)]


class _EtwApi:
    def __init__(self):
        if os.name != "nt" or ct.sizeof(ct.c_void_p) != 8:
            raise OSError("Native ETL replay requires x64 Windows and x64 Python")
        self.advapi = ct.WinDLL("advapi32", use_last_error=True)
        self.tdh = ct.WinDLL("tdh", use_last_error=True)
        self.open = self.advapi.OpenTraceW
        self.open.argtypes = [ct.POINTER(TraceLogfile)]
        self.open.restype = U64
        self.process = self.advapi.ProcessTrace
        self.process.argtypes = [ct.POINTER(U64), U32, ct.c_void_p, ct.c_void_p]
        self.process.restype = U32
        self.close = self.advapi.CloseTrace
        self.close.argtypes = [U64]
        self.close.restype = U32
        args = [ct.POINTER(EventRecord), U32, ct.c_void_p, U32, ct.POINTER(PropertyDescriptor)]
        self.tdh.TdhGetPropertySize.argtypes = [*args, ct.POINTER(U32)]
        self.tdh.TdhGetPropertySize.restype = U32
        self.tdh.TdhGetProperty.argtypes = [*args, U32, ct.c_void_p]
        self.tdh.TdhGetProperty.restype = U32

    def property(self, record, name):
        wide_name = ct.create_unicode_buffer(name)
        descriptor = PropertyDescriptor(ct.addressof(wide_name), 0xFFFFFFFF, 0)
        size = U32()
        args = (record, 0, None, 1, ct.byref(descriptor))
        error = self.tdh.TdhGetPropertySize(*args, ct.byref(size))
        if error or not 0 < size.value <= 65536:
            raise ValueError(f"TDH property unavailable: {name} ({error})")
        data = ct.create_string_buffer(size.value)
        error = self.tdh.TdhGetProperty(*args, size.value, data)
        if error:
            raise ValueError(f"TDH property decode failed: {name} ({error})")
        return data.raw


def decode_record(record, get_property, generation):
    """Strict provider/opcode/version allowlist; never use the event-header actor."""
    header = record.contents.header
    provider = str(UUID(bytes_le=bytes(header.provider)))
    opcode = header.descriptor.opcode
    if provider == LOST_EVENT or (provider == EVENT_TRACE and opcode in {32, 33, 34}):
        raise ValueError("Native ETW lost-event notification")
    kinds = {
        PROCESS: {1: "process_start", 2: "process_end"},
        THREAD: {1: "thread_start", 2: "thread_end"},
        FILE: {
            64: "file_create",
            65: "file_invalidate",
            66: "file_close",
            67: "read",
            68: "write",
            69: "file_invalidate",
            70: "file_invalidate",
            71: "file_invalidate",
        },
    }
    kind = kinds.get(provider, {}).get(opcode)
    if kind is None:
        # Skip only known non-mutating metadata/operations. Unknown operations in
        # these providers could change a lifetime or path and must not be hidden.
        ignored = {
            PROCESS: {3, 4},  # Rundown cannot establish observed process starts.
            THREAD: {3, 4},
            FILE: {0, 32, 35, 36, 72, 73, 74, 76, 77},
        }
        if provider in kinds and opcode not in ignored[provider]:
            raise ValueError("Unsupported kernel event opcode")
        return None
    if header.descriptor.version != 2 or header.flags & 0x60 != 0x40 or not header.flags & 0x100:
        raise ValueError("Unsupported kernel event version or pointer width")

    def number(name, widths=(4,)):
        data = get_property(record, name)
        if len(data) not in widths:
            raise ValueError(f"Unexpected field width: {name}")
        return int.from_bytes(data, "little")

    fields = {}
    if provider == PROCESS:
        fields = {"pid": number("ProcessId"), "process_key": number("UniqueProcessKey", (8,))}
    elif provider == THREAD:
        fields = {"pid": number("ProcessId"), "tid": number("TThreadId")}
    elif provider == FILE:
        fields = {"file_object": number("FileObject", (8,))}
        if kind == "file_create":
            raw = get_property(record, "OpenPath")
            if len(raw) % 2 or not raw.endswith(b"\0\0"):
                raise ValueError("Invalid native path encoding")
            fields["path"] = raw[:-2].decode("utf-16-le", errors="strict")
            if not fields["path"] or "\0" in fields["path"]:
                raise ValueError("Invalid native path")
        elif kind == "write":
            fields.update(tid=number("TTID", (4, 8)), size=number("IoSize"))
    return NativeEvent(generation, header.timestamp, kind, **fields)


def replay_etl(path, *, max_entries=10000, _api=None):
    """Return finalized evidence only. Loss/decode/API failure revokes all writers.

    `_api` is a test seam; the public command always uses the native Windows APIs.
    """
    api = _api or _EtwApi()
    correlation = NativeAttribution(max_entries=max_entries)
    logfile = TraceLogfile()
    logfile.filename = str(Path(path).resolve())
    # EVENT_RECORD + RAW_TIMESTAMP. One ETL/clock/generation per invocation.
    logfile.mode = 0x10000000 | 0x00001000
    callback_type = ct.WINFUNCTYPE if os.name == "nt" else ct.CFUNCTYPE

    def check_loss(log):
        if log.header.events_lost or log.header.buffers_lost or log.events_lost:
            correlation.mark_loss(
                f"ETW loss: header_events={log.header.events_lost}, "
                f"buffers={log.header.buffers_lost}, consumer_events={log.events_lost}"
            )

    @callback_type(None, ct.POINTER(EventRecord))
    def event_callback(record):
        try:
            event = decode_record(record, api.property, correlation.generation)
            if event:
                correlation.accept(event)
        except Exception as error:
            # Exceptions must not escape a ctypes callback (ctypes would swallow them).
            correlation.mark_loss(f"Native decode/processing failure: {error}")

    @callback_type(U32, ct.POINTER(TraceLogfile))
    def buffer_callback(log):
        try:
            check_loss(log.contents)
            return 1
        except Exception:
            correlation.mark_loss("Native buffer callback failed")
            return 0

    logfile.event_callback = ct.cast(event_callback, ct.c_void_p)
    logfile.buffer_callback = ct.cast(buffer_callback, ct.c_void_p)
    handle = api.open(ct.byref(logfile))
    if handle == 0xFFFFFFFFFFFFFFFF:
        raise OSError("OpenTraceW failed; no attribution evidence available")
    complete = False
    try:
        check_loss(logfile)
        if logfile.header.pointer_size != 8 or not logfile.header.end_time:
            correlation.mark_loss("Unsupported pointer size or unfinalized ETL")
        # Circular ETLs can omit starts even without reporting loss; reject the mode.
        if logfile.header.log_mode & 0x2:
            correlation.mark_loss("Circular ETL is outside prototype scope")
        value = U64(handle)
        error = api.process(ct.byref(value), 1, None, None)
        check_loss(logfile)
        complete = error == 0
        if error:
            correlation.mark_loss(f"ProcessTrace failed: {error}")
    finally:
        if api.close(handle):
            correlation.mark_loss("CloseTrace failed")
        correlation.finish(complete=complete)
    return correlation.report()
