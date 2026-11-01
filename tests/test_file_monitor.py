import asyncio
import queue

from src.monitoring.file_monitor import EventInbox, RansomwareEventHandler


class DeferredLoop:
    def __init__(self):
        self.callbacks = []

    def call_soon_threadsafe(self, callback, *args):
        self.callbacks.append((callback, args))

    call_soon = call_soon_threadsafe

    def flush(self):
        while self.callbacks:
            callback, args = self.callbacks.pop(0)
            callback(*args)


def test_metadata_is_filtered(cfg):
    events = queue.Queue()
    loop = DeferredLoop()
    handler = RansomwareEventHandler(events, loop, cfg)
    handler._process_event("created", "repo/.git/index")
    loop.flush()
    assert events.empty()


def test_suspicious_rename_from_ignored_extension_is_preserved(cfg):
    events = queue.Queue()
    loop = DeferredLoop()
    handler = RansomwareEventHandler(events, loop, cfg)
    handler._process_event("moved", "data/document.tmp", "data/document.tmp.enc")
    loop.flush()
    event = events.get_nowait()
    assert event["process"] is None and event["attribution_confidence"] == "unknown"


def test_move_out_of_ignored_directory_is_preserved(cfg):
    events = queue.Queue()
    loop = DeferredLoop()
    handler = RansomwareEventHandler(events, loop, cfg)
    handler._process_event("moved", "data/.git/file", "data/file")
    loop.flush()
    assert events.qsize() == 1


def test_handoff_and_callback_count_are_bounded():
    loop = DeferredLoop()
    events = queue.Queue()
    losses = []
    inbox = EventInbox(events, loop, 16, losses.append)
    for _ in range(1000):
        inbox.offer({"is_canary": False})
    assert len(inbox.pending) == 16 and len(loop.callbacks) == 1
    loop.flush()
    assert sum(losses) == 984 and events.qsize() == 16


def test_canary_prioritized_during_burst():
    loop = DeferredLoop()
    events = queue.Queue()
    losses = []
    inbox = EventInbox(events, loop, 16, losses.append)
    for _ in range(16):
        inbox.offer({"is_canary": False})
    inbox.offer({"is_canary": True})
    loop.flush()
    assert events.get_nowait()["is_canary"] is True
    assert sum(losses) == 1


def test_async_queue_overflow_is_counted():
    loop = DeferredLoop()
    events = asyncio.Queue(maxsize=1)
    losses = []
    inbox = EventInbox(events, loop, 16, losses.append)
    inbox.offer({"type": "one"})
    inbox.offer({"type": "two"})
    loop.flush()
    assert sum(losses) == 1


def test_closed_inbox_does_not_accept_more():
    loop = DeferredLoop()
    inbox = EventInbox(queue.Queue(), loop, 16)
    inbox.close()
    inbox.offer({"type": "x"})
    assert not inbox.pending and not loop.callbacks


def test_intentional_stop_records_discard_without_claiming_overflow():
    loop = DeferredLoop()
    losses, discarded = [], []
    inbox = EventInbox(queue.Queue(), loop, 16, losses.append)
    inbox.offer({"type": "modified"})
    inbox.close(discarded.append)
    assert discarded == [1] and losses == []


def test_overflow_before_intentional_stop_is_still_reported_as_loss():
    loop = DeferredLoop()
    losses, discarded = [], []
    inbox = EventInbox(queue.Queue(), loop, 16, losses.append)
    for _ in range(20):
        inbox.offer({"type": "modified"})
    inbox.close(discarded.append)
    assert losses == [4] and discarded == [16]


def test_watchdog_upstream_is_bounded_and_shutdown_sentinel_does_not_block():
    from watchdog.observers.api import EventDispatcher

    from src.monitoring.file_monitor import LossAwareEventQueue

    losses = []
    events = LossAwareEventQueue(1, losses.append)
    events.put("one")
    events.put("two")
    assert events.qsize() == 1 and sum(losses) == 1
    events.put(EventDispatcher.stop_event)
    assert events.get_nowait() is EventDispatcher.stop_event
