"""
Hybrid Logical Clock (HLC) implementation.

HLC provides causally consistent timestamps across distributed nodes
without requiring synchronized wall clocks. It is the ordering primitive
for the RNA bus genome ledger.

Reference: Kulkarni et al. "Logical Physical Clocks and Consistent
           Snapshots in Globally Distributed Databases" (2014).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Self


@dataclass(order=True, frozen=True)
class HLC:
    """
    Hybrid Logical Clock timestamp.

    Ordering semantics (lexicographic):
      (wall_ms, counter, node_id)

    - wall_ms  : milliseconds since Unix epoch (physical component)
    - counter  : logical tiebreaker, incremented when wall_ms ties
    - node_id  : node UUID (final tiebreaker for total order)
    """

    wall_ms: int
    counter: int
    node_id: str

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def zero(cls, node_id: str = "") -> Self:
        return cls(wall_ms=0, counter=0, node_id=node_id)

    @classmethod
    def now(cls, node_id: str, local: Self | None = None) -> Self:
        """
        Generate a new HLC tick for *this* node.

        If *local* is provided it is the node's last known HLC; the new
        clock advances past it even when the wall clock goes backward.
        """
        wall = _wall_ms()
        if local is None:
            return cls(wall_ms=wall, counter=0, node_id=node_id)

        if wall > local.wall_ms:
            return cls(wall_ms=wall, counter=0, node_id=node_id)
        # Wall clock did not advance — bump the logical counter.
        return cls(wall_ms=local.wall_ms, counter=local.counter + 1, node_id=node_id)

    @classmethod
    def recv(cls, local: Self, remote: Self, node_id: str) -> Self:
        """
        Merge *remote* into *local* when receiving an event.

        Returns the new local HLC that is strictly greater than both.
        """
        wall = _wall_ms()
        max_wall = max(wall, local.wall_ms, remote.wall_ms)

        if max_wall == local.wall_ms == remote.wall_ms:
            counter = max(local.counter, remote.counter) + 1
        elif max_wall == local.wall_ms:
            counter = local.counter + 1
        elif max_wall == remote.wall_ms:
            counter = remote.counter + 1
        else:
            counter = 0

        return cls(wall_ms=max_wall, counter=counter, node_id=node_id)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {"wall_ms": self.wall_ms, "counter": self.counter, "node_id": self.node_id}

    @classmethod
    def from_dict(cls, d: dict) -> Self:
        return cls(wall_ms=d["wall_ms"], counter=d["counter"], node_id=d["node_id"])

    def __str__(self) -> str:
        return f"HLC({self.wall_ms},{self.counter},{self.node_id[:8]})"


# ---------------------------------------------------------------------------
# Module-level HLC state for a single process
# ---------------------------------------------------------------------------


class HLCClock:
    """
    Stateful HLC that a node uses to stamp its own events.

    Usage::

        clock = HLCClock(node_id="abc123")
        t1 = clock.tick()          # generate local event timestamp
        t2 = clock.recv(remote_t)  # merge received timestamp
    """

    def __init__(self, node_id: str, initial: HLC | None = None) -> None:
        self.node_id = node_id
        self._local: HLC = initial or HLC.zero(node_id)

    def tick(self) -> HLC:
        """Advance clock for a locally generated event."""
        self._local = HLC.now(self.node_id, self._local)
        return self._local

    def recv(self, remote: HLC) -> HLC:
        """Advance clock after receiving a remote event."""
        self._local = HLC.recv(self._local, remote, self.node_id)
        return self._local

    @property
    def current(self) -> HLC:
        return self._local


def _wall_ms() -> int:
    return int(time.time() * 1000)
