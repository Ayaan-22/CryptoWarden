from unittest.mock import Mock

import pytest

from src.analysis.native_attribution import NativeAttribution, NativeEvent
from src.models import ProcessIdentity
from src.response.responder import Responder

PATH = r"\Device\HarddiskVolume3\protected\document.txt"


def send(collector, timestamp, kind, **fields):
    collector.accept(NativeEvent(collector.generation, timestamp, kind, **fields))


def opened_writer(collector=None):
    collector = collector or NativeAttribution()
    send(collector, 1, "process_start", pid=10, process_key=100)
    send(collector, 2, "thread_start", pid=10, tid=11)
    send(collector, 3, "file_create", file_object=500, path=PATH)
    return collector


def write(collector, timestamp=4, tid=11, file_object=500, size=4096):
    send(collector, timestamp, "write", tid=tid, file_object=file_object, size=size)


def finalized(collector):
    collector.finish(complete=True)
    return collector.writes()


def test_only_native_write_request_establishes_unqualified_correlation():
    collector = opened_writer()
    send(collector, 4, "read", tid=11, file_object=500)
    assert not collector.writes()
    write(collector, 5)
    assert collector.writes()[0].status == "unknown"  # Final loss totals are not known yet.
    row = finalized(collector)[0]
    assert row.status == "native_correlated"
    assert row.writer.pid == 10 and row.writer.process_key == 100
    assert row.file_started == 3 and row.thread_started == 2
    assert row.requested_bytes == 4096
    assert collector.report()["qualified"] is False
    assert collector.report()["automatic_termination"] is False


def test_reader_and_unrelated_high_io_process_cannot_replace_issuing_thread():
    collector = opened_writer()
    send(collector, 4, "process_start", pid=20, process_key=200)
    send(collector, 5, "thread_start", pid=20, tid=21)
    send(collector, 6, "read", tid=21, file_object=500)
    send(collector, 7, "file_create", file_object=600, path=r"C:\unrelated")
    write(collector, 8, tid=21, file_object=600, size=999999999)
    write(collector, 9)
    finalized(collector)
    status, writer = collector.attribute_path(PATH.upper(), 4, 10)
    assert status == "native_correlated" and writer.pid == 10


def test_missing_thread_never_falls_back_to_file_opener():
    collector = opened_writer()
    write(collector, tid=999)
    row = finalized(collector)[0]
    assert row.status == "unknown" and row.writer is None


def test_pid_reuse_requires_new_thread_lifetime_and_retains_original_snapshot():
    collector = opened_writer()
    write(collector)
    send(collector, 5, "process_end", pid=10, process_key=100)
    send(collector, 6, "process_start", pid=10, process_key=200)
    write(collector, 7)  # Old TID must not bind to replacement PID.
    send(collector, 8, "thread_start", pid=10, tid=11)
    write(collector, 9)
    old, unresolved, new = finalized(collector)
    assert old.writer.process_key == 100 and old.writer.started == 1
    assert unresolved.status == "unknown" and unresolved.writer is None
    assert new.writer.process_key == 200 and new.writer.started == 6
    assert collector.attribute_path(PATH, 1, 10) == ("unknown", None)


def test_thread_id_reuse_binds_to_new_process_only_after_observed_start():
    collector = opened_writer()
    send(collector, 4, "thread_end", pid=10, tid=11)
    write(collector, 5)
    send(collector, 6, "process_start", pid=20, process_key=200)
    send(collector, 7, "thread_start", pid=20, tid=11)
    write(collector, 8)
    unknown, new = finalized(collector)
    assert unknown.writer is None and new.writer.pid == 20


def test_short_lived_writer_survives_exit_without_live_process_lookup():
    collector = opened_writer()
    write(collector)
    send(collector, 5, "thread_end", pid=10, tid=11)
    send(collector, 6, "process_end", pid=10, process_key=100)
    row = finalized(collector)[0]
    assert not collector.processes and not collector.threads
    assert row.status == "native_correlated" and row.writer.started == 1
    # This is a trace instance, deliberately incompatible with response identities.
    assert not isinstance(row.writer, ProcessIdentity)


def test_short_lived_writer_missing_start_remains_unknown():
    collector = NativeAttribution()
    send(collector, 1, "thread_start", pid=10, tid=11)
    send(collector, 2, "file_create", file_object=500, path=PATH)
    write(collector)
    send(collector, 5, "process_end", pid=10, process_key=100)
    assert finalized(collector)[0].writer is None


def test_two_native_writers_to_same_path_are_ambiguous_for_path_query():
    collector = opened_writer()
    write(collector)
    send(collector, 5, "process_start", pid=20, process_key=200)
    send(collector, 6, "thread_start", pid=20, tid=21)
    send(collector, 7, "file_create", file_object=600, path=PATH)
    write(collector, 8, tid=21, file_object=600)
    rows = finalized(collector)
    assert [row.writer.pid for row in rows] == [10, 20]
    assert collector.attribute_path(PATH, 1, 10) == ("unknown", None)
    assert collector.attribute_path(PATH, 4, 4)[1].pid == 10


@pytest.mark.parametrize("kind", ["file_close", "file_invalidate"])
def test_file_object_reuse_does_not_inherit_old_path(kind):
    collector = opened_writer()
    write(collector)
    send(collector, 5, kind, file_object=500)
    write(collector, 6)
    send(collector, 7, "file_create", file_object=500, path=r"C:\new.txt")
    write(collector, 8)
    old, unknown, new = finalized(collector)
    assert old.path == PATH
    assert unknown.path is None and unknown.writer is None
    assert new.path == r"C:\new.txt" and new.file_started == 7


@pytest.mark.parametrize(
    "failure",
    [
        "ETW events lost",
        "ETW buffers lost",
        "Consumer queue overflow",
        "TDH decode failed",
        "Collector disconnected",
    ],
)
def test_loss_revokes_earlier_writers_and_does_not_recover_in_same_generation(failure):
    collector = opened_writer()
    write(collector)
    collector.mark_loss(failure)
    send(collector, 5, "process_start", pid=10, process_key=200)
    send(collector, 6, "thread_start", pid=10, tid=11)
    send(collector, 7, "file_create", file_object=500, path=PATH)
    write(collector, 8)
    assert all(row.status == "unknown" and row.writer is None for row in finalized(collector))
    assert collector.report()["issues"] == [failure]
    fresh = opened_writer()
    write(fresh)
    assert finalized(fresh)[0].status == "native_correlated"
    assert fresh.generation != collector.generation


def test_stale_generation_and_out_of_order_events_taint_all_results():
    collector = opened_writer()
    write(collector)
    collector.accept(NativeEvent("old-generation", 5, "write", tid=11, file_object=500))
    send(collector, 2, "thread_end", tid=11, pid=10)
    assert finalized(collector)[0].writer is None
    assert len(collector.issues) == 2


@pytest.mark.parametrize("table", ["process", "thread", "file", "writes"])
def test_capacity_overflow_is_visible_and_revokes_generation(table):
    collector = opened_writer(NativeAttribution(max_entries=1))
    write(collector)
    if table == "process":
        send(collector, 5, "process_start", pid=20, process_key=200)
    elif table == "thread":
        send(collector, 5, "thread_start", pid=10, tid=12)
    elif table == "file":
        send(collector, 5, "file_create", file_object=600, path=PATH)
    else:
        write(collector, 5)
    assert finalized(collector)[0].writer is None
    assert "capacity exceeded" in collector.issues[0]
    assert not collector.processes and not collector.files and not collector.threads


@pytest.mark.parametrize(
    "kind,fields",
    [
        ("process_start", {"pid": 10, "process_key": 200}),
        ("process_end", {"pid": 10, "process_key": 200}),
        ("thread_start", {"pid": 10, "tid": 11}),
        ("thread_end", {"pid": 20, "tid": 11}),
        ("file_create", {"file_object": 500, "path": PATH}),
    ],
)
def test_overlapping_or_mismatched_lifetimes_are_not_guessed(kind, fields):
    collector = opened_writer()
    write(collector)
    send(collector, 5, kind, **fields)
    assert finalized(collector)[0].status == "unknown" and collector.issues


@pytest.mark.parametrize(
    "kind,fields",
    [
        ("process_end", {"pid": 10, "process_key": 100}),
        ("thread_end", {"pid": 10, "tid": 11}),
        ("file_close", {"file_object": 500}),
        ("file_invalidate", {"file_object": 500}),
    ],
)
def test_equal_clock_exit_or_close_cannot_prove_write_order(kind, fields):
    collector = opened_writer()
    write(collector)
    send(collector, 4, kind, **fields)
    assert finalized(collector)[0].writer is None


def test_equal_clock_create_and_zero_byte_write_remain_unknown():
    collector = opened_writer()
    write(collector, 3)
    write(collector, 4, size=0)
    assert all(row.writer is None for row in finalized(collector))


def test_incomplete_replay_never_exposes_writer_and_finalized_replay_is_closed():
    collector = opened_writer()
    write(collector)
    collector.finish(complete=False)
    assert collector.writes()[0].writer is None
    assert collector.report()["complete"] is False
    with pytest.raises(RuntimeError, match="finalized"):
        write(collector, 5)


def test_missing_file_mapping_poisoning_path_query_cannot_choose_nearest_writer():
    collector = opened_writer()
    write(collector)
    write(collector, 5, file_object=999)
    finalized(collector)
    assert collector.attribute_path(PATH, 1, 10) == ("unknown", None)


def test_native_prototype_evidence_cannot_authorize_automatic_response(cfg):
    collector = opened_writer()
    write(collector)
    row = finalized(collector)[0]
    cfg["response"]["mode"] = "terminate"
    factory = Mock()
    responder = Responder(cfg["response"], factory)
    assert responder.take_action(row.writer, "native prototype").status == "refused"
    assert responder.take_action(row.writer, "native prototype", manual=True).status == "refused"
    # Even a response-shaped identity cannot bypass the qualification gate.
    identity = ProcessIdentity(10, 1, "writer.exe", r"C:\writer.exe")
    assert responder.take_action(identity, "native_correlated").status == "refused"
    factory.assert_not_called()
