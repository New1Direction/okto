"""
Tests for the Traffic Session Inspector:
  - EventBus subscribe/publish/unsubscribe
  - EventBus history replay for late joiners
  - FastAPI REST endpoints: /api/sessions, /api/sessions/{id}, /api/genome
  - WebSocket live stream at /ws/live
  - Replay endpoint: POST /api/sessions/{id}/replay
  - Provider detection utility
"""

from __future__ import annotations

import asyncio
import json
import pathlib

import orjson
import pytest
from fastapi.testclient import TestClient

from selfhswarm.hlc import HLCClock
from selfhswarm.models import (
    AgentClient,
    HLCModel,
    LiveEvent,
    LiveEventType,
    Session,
    StreamChunk,
    Turn,
    detect_provider,
)
from selfhswarm.viewer.events import EventBus
from selfhswarm.viewer.server import create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_session_dir(tmp_path: pathlib.Path) -> str:
    return str(tmp_path)


@pytest.fixture
def sample_session(tmp_path: pathlib.Path) -> tuple[Session, pathlib.Path]:
    clock = HLCClock("test-node")
    hlc = HLCModel.from_hlc(clock.tick())
    session = Session(
        id="sess-00000001-test",
        client=AgentClient.CLAUDE,
        node_id="test-node",
        started_at_hlc=hlc,
        connect_target="api.anthropic.com:443",
        tls_established=True,
    )
    # Add a turn with one anomalous chunk
    raw = b'{"choices":[{"delta":{"content":"hi"}}]}'
    expected = b'data: {"choices":[{"delta":{"content":"hi"}}]}'
    chunk = StreamChunk(
        index=0,
        raw_hex=raw.hex(),
        anomalous=True,
        anomaly_type="bare_json_without_data_prefix",
        expected_hex=expected.hex(),
    )
    turn = Turn(
        index=0,
        started_at_hlc=hlc,
        stream_chunks=[chunk],
        anomalies_detected=1,
    )
    session.turns.append(turn)

    # Persist to tmp dir
    p = tmp_path / f"{session.id}.jsonl"
    p.write_bytes(orjson.dumps(session.model_dump()))
    return session, p


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def app(bus: EventBus, tmp_session_dir: str):
    return create_app(bus, tmp_session_dir, "test-node-id")


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------


class TestEventBus:
    @pytest.mark.asyncio
    async def test_subscribe_receive_event(self):
        bus = EventBus()
        q = bus.subscribe(replay_history=False)
        ev = LiveEvent(type=LiveEventType.SESSION_START, session_id="s1")
        await bus.publish(ev)
        got = await asyncio.wait_for(q.get(), timeout=1.0)
        assert got.session_id == "s1"
        assert got.type == LiveEventType.SESSION_START

    @pytest.mark.asyncio
    async def test_multiple_subscribers_all_receive(self):
        bus = EventBus()
        q1 = bus.subscribe(replay_history=False)
        q2 = bus.subscribe(replay_history=False)
        ev = LiveEvent(type=LiveEventType.ANOMALY_DETECTED, session_id="s2")
        await bus.publish(ev)
        got1 = await asyncio.wait_for(q1.get(), timeout=1.0)
        got2 = await asyncio.wait_for(q2.get(), timeout=1.0)
        assert got1.session_id == got2.session_id == "s2"

    @pytest.mark.asyncio
    async def test_unsubscribe_stops_delivery(self):
        bus = EventBus()
        q = bus.subscribe(replay_history=False)
        assert bus.subscriber_count == 1
        bus.unsubscribe(q)
        assert bus.subscriber_count == 0
        # Publish after unsubscribe should not raise
        await bus.publish(LiveEvent(type=LiveEventType.SESSION_END, session_id="s3"))

    @pytest.mark.asyncio
    async def test_history_replay_for_late_joiner(self):
        bus = EventBus()
        # Publish before anyone subscribes
        for i in range(3):
            await bus.publish(LiveEvent(type=LiveEventType.SESSION_START, session_id=f"s{i}"))
        # Late joiner gets history
        q = bus.subscribe(replay_history=True)
        events = []
        for _ in range(3):
            events.append(await asyncio.wait_for(q.get(), timeout=1.0))
        assert {e.session_id for e in events} == {"s0", "s1", "s2"}

    @pytest.mark.asyncio
    async def test_no_history_when_replay_false(self):
        bus = EventBus()
        await bus.publish(LiveEvent(type=LiveEventType.SESSION_START, session_id="s_old"))
        q = bus.subscribe(replay_history=False)
        # Should not receive the old event
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(q.get(), timeout=0.1)

    @pytest.mark.asyncio
    async def test_full_queue_drops_oldest_not_stall(self):
        bus = EventBus(maxsize=2)
        q = bus.subscribe(replay_history=False)
        # Fill the queue
        for i in range(5):
            await bus.publish(LiveEvent(type=LiveEventType.SESSION_START, session_id=f"s{i}"))
        # Must not block or raise — queue should have 2 events (some dropped)
        count = 0
        while not q.empty():
            q.get_nowait()
            count += 1
        assert count <= 2


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------


class TestProviderDetection:
    def test_anthropic(self):
        p = detect_provider("api.anthropic.com")
        assert p.vendor == "Anthropic"
        assert p.product == "Claude"

    def test_openai(self):
        p = detect_provider("api.openai.com")
        assert p.vendor == "OpenAI"

    def test_gemini(self):
        p = detect_provider("generativelanguage.googleapis.com")
        assert p.vendor == "Google"
        assert p.product == "Gemini"

    def test_unknown(self):
        p = detect_provider("mystery.api.example.com")
        assert p.vendor == "Unknown"
        assert p.hostname == "mystery.api.example.com"

    def test_hostname_stored(self):
        p = detect_provider("api.openai.com")
        assert p.hostname == "api.openai.com"


# ---------------------------------------------------------------------------
# REST endpoints (synchronous TestClient)
# ---------------------------------------------------------------------------


class TestRestEndpoints:
    def test_dashboard_html_served(self, client: TestClient):
        """GET / should return the dashboard HTML."""
        r = client.get("/")
        assert r.status_code == 200
        assert "Okto" in r.text
        assert "Traffic Inspector" in r.text

    def test_sessions_empty(self, client: TestClient):
        r = client.get("/api/sessions")
        assert r.status_code == 200
        assert r.json() == []

    def test_sessions_lists_persisted(
        self, bus: EventBus, tmp_session_dir: str, sample_session: tuple
    ):
        session, _ = sample_session
        # Copy to the app's session_dir
        p = pathlib.Path(tmp_session_dir) / f"{session.id}.jsonl"
        p.write_bytes(orjson.dumps(session.model_dump()))

        app = create_app(bus, tmp_session_dir, "test-node")
        c = TestClient(app)
        r = c.get("/api/sessions")
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["id"] == session.id
        assert data[0]["connect_target"] == "api.anthropic.com:443"
        assert data[0]["tls_established"] is True
        assert data[0]["anomaly_count"] == 1

    def test_get_session_detail(
        self, bus: EventBus, tmp_session_dir: str, sample_session: tuple
    ):
        session, _ = sample_session
        p = pathlib.Path(tmp_session_dir) / f"{session.id}.jsonl"
        p.write_bytes(orjson.dumps(session.model_dump()))

        app = create_app(bus, tmp_session_dir, "test-node")
        c = TestClient(app)
        r = c.get(f"/api/sessions/{session.id}")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == session.id
        assert len(data["turns"]) == 1

    def test_get_session_not_found(self, client: TestClient):
        r = client.get("/api/sessions/nonexistent-id")
        assert r.status_code == 404

    def test_genome_endpoint_no_ledger(self, client: TestClient):
        r = client.get("/api/genome")
        assert r.status_code == 200
        data = r.json()
        assert data["mutations"] == []
        assert data["count"] == 0

    def test_replay_not_found(self, client: TestClient):
        r = client.post("/api/sessions/nonexistent/replay")
        assert r.status_code == 404

    def test_replay_session_resolves_anomaly(
        self, bus: EventBus, tmp_session_dir: str, sample_session: tuple
    ):
        """Replay should detect the anomaly and apply the genome mutation."""
        session, _ = sample_session
        p = pathlib.Path(tmp_session_dir) / f"{session.id}.jsonl"
        p.write_bytes(orjson.dumps(session.model_dump()))

        app = create_app(bus, tmp_session_dir, "test-node")
        c = TestClient(app)
        r = c.post(f"/api/sessions/{session.id}/replay")
        assert r.status_code == 200
        result = r.json()
        assert result["session_id"] == session.id
        assert result["total_anomalies"] == 1
        assert len(result["turn_results"]) == 1
        tr = result["turn_results"][0]
        assert tr["anomalies_detected"] == 1
        # The state machine should derive a new mutation during replay
        # so the chunk is either patched by genome or newly derived
        anomalous_chunks = [c for c in tr["chunks"] if c["anomalous"]]
        assert len(anomalous_chunks) == 1
        assert anomalous_chunks[0]["anomaly_type"] == "bare_json_without_data_prefix"


# ---------------------------------------------------------------------------
# WebSocket live stream
# ---------------------------------------------------------------------------


class TestWebSocketLive:
    def test_websocket_receives_published_event(
        self, app, bus: EventBus
    ):
        """Events published after WS connect should arrive immediately."""
        with TestClient(app) as c:
            with c.websocket_connect("/ws/live") as ws:
                ev = LiveEvent(
                    type=LiveEventType.MUTATION_DERIVED,
                    session_id="ws-test-session",
                    payload={"mutation": {"id": "abc"}},
                )
                bus._publish_sync(ev)

                data = ws.receive_text()
                parsed = json.loads(data)
                assert parsed["session_id"] == "ws-test-session"
                assert parsed["type"] == "mutation_derived"

    def test_websocket_history_replay_on_connect(
        self, bus: EventBus, tmp_session_dir: str
    ):
        """Events published before WS connect should arrive via history replay."""

        async def _publish_history():
            await bus.publish(
                LiveEvent(
                    type=LiveEventType.SESSION_START,
                    session_id="hist-session",
                )
            )

        asyncio.run(_publish_history())

        app = create_app(bus, tmp_session_dir, "test-node")
        with TestClient(app) as c:
            with c.websocket_connect("/ws/live") as ws:
                data = ws.receive_text()
                parsed = json.loads(data)
                assert parsed["session_id"] == "hist-session"
