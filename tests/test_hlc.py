"""Tests for the Hybrid Logical Clock."""

import time

import pytest

from selfhswarm.hlc import HLC, HLCClock


def test_hlc_ordering_wall_clock():
    a = HLC(wall_ms=1000, counter=0, node_id="a")
    b = HLC(wall_ms=2000, counter=0, node_id="a")
    assert a < b


def test_hlc_ordering_counter_tiebreak():
    a = HLC(wall_ms=1000, counter=0, node_id="a")
    b = HLC(wall_ms=1000, counter=1, node_id="a")
    assert a < b


def test_hlc_ordering_node_tiebreak():
    a = HLC(wall_ms=1000, counter=0, node_id="aaa")
    b = HLC(wall_ms=1000, counter=0, node_id="bbb")
    assert a < b


def test_hlc_now_monotonic():
    """Two successive ticks from the same clock must be strictly increasing."""
    clock = HLCClock("node-1")
    t1 = clock.tick()
    t2 = clock.tick()
    assert t1 < t2


def test_hlc_recv_advances_past_remote():
    """After receiving a future remote timestamp, local clock advances past it."""
    clock = HLCClock("node-1")
    far_future = HLC(wall_ms=int(time.time() * 1000) + 100_000, counter=99, node_id="remote")
    merged = clock.recv(far_future)
    assert merged > far_future


def test_hlc_serialization_roundtrip():
    h = HLC(wall_ms=123456789, counter=42, node_id="abc")
    assert HLC.from_dict(h.to_dict()) == h


def test_hlc_clock_state():
    clock = HLCClock("n")
    t1 = clock.tick()
    assert clock.current == t1
    t2 = clock.tick()
    assert clock.current == t2
    assert t2 > t1
