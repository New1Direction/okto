"""
Traffic Session Inspector — FastAPI viewer server.

Endpoints
─────────
  GET  /                       → dashboard HTML
  GET  /api/sessions           → list sessions from session_dir
  GET  /api/sessions/{id}      → full session detail
  POST /api/sessions/{id}/replay → replay chunks through a fresh state machine
  WS   /ws/live                → WebSocket stream of LiveEvents
  GET  /api/genome             → current genome mutation list
"""

from __future__ import annotations

import asyncio
import logging
import pathlib

import orjson
import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from selfhswarm.models import ReplayResult, Session
from selfhswarm.replay import replay_session as run_replay
from selfhswarm.viewer.events import EventBus

log = logging.getLogger(__name__)

_STATIC_DIR = pathlib.Path(__file__).parent / "static"


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(
    event_bus: EventBus,
    session_dir: str,
    node_id: str,
    ledger=None,  # GenomeLedger | None
) -> FastAPI:
    """
    Build and return the FastAPI viewer application.

    *event_bus*   receives LiveEvent objects from the proxy.
    *session_dir* is where session JSONL files are written by the proxy.
    *ledger*      is the live genome ledger (optional, for genome endpoint).
    """
    session_path = pathlib.Path(session_dir)

    app = FastAPI(title="Okto Traffic Inspector", docs_url=None, redoc_url=None)

    # ------------------------------------------------------------------
    # HTML dashboard
    # ------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard():
        html_path = _STATIC_DIR / "index.html"
        if html_path.exists():
            return HTMLResponse(html_path.read_text())
        raise HTTPException(status_code=404, detail="Dashboard not built")

    # ------------------------------------------------------------------
    # REST: sessions
    # ------------------------------------------------------------------

    @app.get("/api/sessions")
    async def list_sessions() -> list[dict]:
        """List all sessions (summary view) sorted newest-first."""
        results = []
        for p in sorted(session_path.glob("*.jsonl"), reverse=True)[:100]:
            try:
                data = orjson.loads(p.read_bytes())
                s = Session.model_validate(data)
                results.append(_session_summary(s))
            except Exception as exc:
                log.warning("Failed to parse session %s: %s", p.name, exc)
        return results

    @app.get("/api/sessions/{session_id}")
    async def get_session(session_id: str) -> dict:
        """Return full session detail including all turns and chunks."""
        p = session_path / f"{session_id}.jsonl"
        if not p.exists():
            raise HTTPException(status_code=404, detail="Session not found")
        try:
            data = orjson.loads(p.read_bytes())
            return data
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/sessions/{session_id}/replay")
    async def replay_session(session_id: str) -> ReplayResult:
        """
        Replay all turns in a session through a fresh ProxyStateMachine.

        Uses the current genome from the ledger so improvements since the
        original run are applied.  Returns per-chunk before/after results.
        """
        p = session_path / f"{session_id}.jsonl"
        if not p.exists():
            raise HTTPException(status_code=404, detail="Session not found")

        session = Session.model_validate(orjson.loads(p.read_bytes()))
        mutations = (
            ledger.genome.for_client(session.client) if ledger else []
        )
        return run_replay(session, mutations, node_id)

    # ------------------------------------------------------------------
    # REST: genome
    # ------------------------------------------------------------------

    @app.get("/api/genome")
    async def get_genome() -> dict:
        if not ledger:
            return {"mutations": [], "count": 0}
        muts = [m.model_dump() for m in ledger.genome.sorted()]
        return {"mutations": muts, "count": len(muts), "node_id": node_id}

    # ------------------------------------------------------------------
    # WebSocket: live events
    # ------------------------------------------------------------------

    @app.websocket("/ws/live")
    async def ws_live(websocket: WebSocket):
        await websocket.accept()
        q = event_bus.subscribe(replay_history=True)
        log.debug(
            "WebSocket client connected (%d total)", event_bus.subscriber_count
        )
        try:
            while True:
                event = await q.get()
                await websocket.send_text(event.model_dump_json())
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            event_bus.unsubscribe(q)
            log.debug(
                "WebSocket client disconnected (%d remaining)",
                event_bus.subscriber_count,
            )

    # ------------------------------------------------------------------
    # Static files (fallthrough for /static/*)
    # ------------------------------------------------------------------

    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    return app


# ---------------------------------------------------------------------------
# Summary helper
# ---------------------------------------------------------------------------


def _session_summary(s: Session) -> dict:
    anomaly_count = sum(
        chunk.anomalous
        for turn in s.turns
        for chunk in turn.stream_chunks
    )
    mutation_ids: set[str] = set()
    for turn in s.turns:
        for mid in turn.mutations_applied:
            mutation_ids.add(mid)

    return {
        "id": s.id,
        "client": s.client.value,
        "connect_target": s.connect_target,
        "tls_established": s.tls_established,
        "provider": s.provider.model_dump() if s.provider else None,
        "turn_count": len(s.turns),
        "anomaly_count": anomaly_count,
        "mutation_count": len(mutation_ids),
        "started_at_ms": s.started_at_hlc.wall_ms,
    }


# ---------------------------------------------------------------------------
# Server lifecycle helper
# ---------------------------------------------------------------------------


async def start_viewer(
    event_bus: EventBus,
    session_dir: str,
    node_id: str,
    ledger=None,
    host: str = "127.0.0.1",
    port: int = 7878,
) -> asyncio.Task:
    """
    Start the viewer server in a background asyncio task.

    Returns the task so the caller can cancel it on shutdown.
    """
    app = create_app(event_bus, session_dir, node_id, ledger)
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    return task
