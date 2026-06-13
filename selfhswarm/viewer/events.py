"""
EventBus — async pub/sub for live proxy events.

The proxy emits LiveEvent objects to the bus. The FastAPI viewer
subscribes one asyncio.Queue per WebSocket connection and reads from it.

Usage::

    bus = EventBus()

    # In proxy (emitter):
    await bus.publish(LiveEvent(type=LiveEventType.ANOMALY_DETECTED, ...))

    # In WebSocket handler (subscriber):
    q = bus.subscribe()
    try:
        while True:
            event = await q.get()
            await ws.send_text(event.model_dump_json())
    finally:
        bus.unsubscribe(q)
"""

from __future__ import annotations

import asyncio
import logging

from selfhswarm.models import LiveEvent

log = logging.getLogger(__name__)


class EventBus:
    """
    In-process async event bus with multicast delivery.

    All emitted events are placed into every active subscriber queue.
    Slow subscribers are not penalised — if a queue is full its oldest
    event is discarded (so live viewers can't stall the proxy).
    """

    def __init__(self, maxsize: int = 2000) -> None:
        self._maxsize = maxsize
        self._subscribers: list[asyncio.Queue[LiveEvent]] = []
        self._history: list[LiveEvent] = []   # last N events for catch-up
        self._history_limit = 500

    async def publish(self, event: LiveEvent) -> None:
        """Publish an event to all subscribers."""
        self._history.append(event)
        if len(self._history) > self._history_limit:
            self._history = self._history[-self._history_limit:]

        dead: list[asyncio.Queue] = []
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Drop oldest item and retry
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    dead.append(q)
        for q in dead:
            self._safe_remove(q)

    def subscribe(self, replay_history: bool = True) -> asyncio.Queue[LiveEvent]:
        """
        Create a new subscriber queue.

        If *replay_history* is True, the current history snapshot is
        pre-populated into the queue so a newly connected client sees
        the state of all recent sessions immediately.
        """
        q: asyncio.Queue[LiveEvent] = asyncio.Queue(maxsize=self._maxsize)
        if replay_history:
            for ev in self._history:
                try:
                    q.put_nowait(ev)
                except asyncio.QueueFull:
                    break
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[LiveEvent]) -> None:
        """Remove a subscriber queue (call on WebSocket disconnect)."""
        self._safe_remove(q)

    def _safe_remove(self, q: asyncio.Queue) -> None:
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    def _publish_sync(self, event: LiveEvent) -> None:
        """Synchronous publish for test helpers — not for production async contexts."""
        self._history.append(event)
        if len(self._history) > self._history_limit:
            self._history = self._history[-self._history_limit:]
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)
