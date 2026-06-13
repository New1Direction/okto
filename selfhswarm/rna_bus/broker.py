"""
Layer 3 — RNA Bus: WebSocket broker.

The broker is a hub-and-spoke server that:
  1. Accepts HELLO from nodes with their current genome HLC
  2. Sends DELTA (mutations the node is missing)
  3. Accepts PUSH (new mutations from a node)
  4. BROADCASTs pushed mutations to all other connected nodes

The broker can run locally (selfhswarm broker) for a LAN swarm,
or a shared public instance can be used for cross-machine swarms.

Protocol (JSON over WebSocket):
  → HELLO  { node_id, hlc: {wall_ms, counter, node_id} }
  ← DELTA  { mutations: [...] }
  → PUSH   { mutation: {...} }
  ← BROADCAST { mutation: {...} }
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import orjson
import websockets
from websockets.asyncio.server import serve, ServerConnection

from selfhswarm.hlc import HLC, HLCClock
from selfhswarm.models import BusMessage, BusMessageType, HLCModel, Mutation

log = logging.getLogger(__name__)


class RNABroker:
    """
    Central WebSocket broker for the RNA bus.

    Maintains the authoritative append-only ledger of all known mutations
    and fans them out to connected nodes.
    """

    def __init__(self, node_id: str = "broker") -> None:
        self._clock = HLCClock(node_id)
        self._mutations: list[Mutation] = []  # append-only in HLC order
        self._connections: dict[str, ServerConnection] = {}

    async def serve(self, host: str = "0.0.0.0", port: int = 9373) -> None:
        log.info("RNA broker listening on ws://%s:%s", host, port)
        async with serve(self._handle, host, port):
            await asyncio.Future()  # run forever

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def _handle(self, ws: ServerConnection) -> None:
        node_id: str | None = None
        try:
            async for raw in ws:
                msg = BusMessage.model_validate(orjson.loads(raw))
                node_id = msg.node_id

                if msg.type == BusMessageType.HELLO:
                    await self._on_hello(ws, msg)
                elif msg.type == BusMessageType.PUSH:
                    await self._on_push(ws, msg)
                else:
                    log.warning("Unknown message type from %s: %s", node_id, msg.type)

        except websockets.exceptions.ConnectionClosedOK:
            pass
        except Exception as exc:
            log.error("Connection error for %s: %s", node_id, exc)
        finally:
            if node_id and node_id in self._connections:
                del self._connections[node_id]
                log.info("Node disconnected: %s (%d remaining)", node_id, len(self._connections))

    async def _on_hello(self, ws: ServerConnection, msg: BusMessage) -> None:
        node_id = msg.node_id
        self._connections[node_id] = ws
        log.info("Node connected: %s", node_id)

        # Compute delta: mutations newer than the node's reported HLC
        node_hlc_data = msg.payload.get("hlc")
        if node_hlc_data:
            node_hlc = HLC.from_dict(node_hlc_data)
            delta = [m for m in self._mutations if m.hlc.to_hlc() > node_hlc]
        else:
            delta = list(self._mutations)

        response = BusMessage(
            type=BusMessageType.DELTA,
            node_id="broker",
            payload={"mutations": [m.model_dump() for m in delta]},
        )
        await ws.send(orjson.dumps(response.model_dump()).decode())
        log.debug("Sent delta of %d mutations to %s", len(delta), node_id)

    async def _on_push(self, ws: ServerConnection, msg: BusMessage) -> None:
        node_id = msg.node_id
        try:
            mut = Mutation.model_validate(msg.payload["mutation"])
        except Exception as exc:
            log.error("Invalid mutation from %s: %s", node_id, exc)
            return

        # Advance broker HLC
        remote_hlc = mut.hlc.to_hlc()
        self._clock.recv(remote_hlc)

        # Append to authoritative ledger
        self._mutations.append(mut)
        self._mutations.sort(key=lambda m: m.hlc)
        log.info(
            "New mutation from %s: scope=%s client=%s confidence=%.2f",
            node_id, mut.scope, mut.client, mut.confidence,
        )

        # Broadcast to all other nodes
        broadcast = BusMessage(
            type=BusMessageType.BROADCAST,
            node_id="broker",
            payload={"mutation": mut.model_dump()},
        )
        broadcast_bytes = orjson.dumps(broadcast.model_dump()).decode()
        dead_nodes = []
        for nid, conn in self._connections.items():
            if nid == node_id:
                continue
            try:
                await conn.send(broadcast_bytes)
            except Exception:
                dead_nodes.append(nid)
        for nid in dead_nodes:
            del self._connections[nid]


class RNAClient:
    """
    Client-side RNA bus connection.

    Connects to the broker, syncs missing mutations, and streams new
    mutations as they are discovered locally.
    """

    def __init__(
        self,
        node_id: str,
        broker_url: str,
        ledger,  # GenomeLedger
        clock: HLCClock,
    ) -> None:
        self.node_id = node_id
        self.broker_url = broker_url
        self.ledger = ledger
        self.clock = clock
        self._ws: Any = None
        self._running = False

    async def connect(self) -> None:
        """Connect and sync, then listen for broadcasts in background."""
        self._running = True
        asyncio.create_task(self._run())

    async def _run(self) -> None:
        while self._running:
            try:
                async with websockets.connect(self.broker_url) as ws:
                    self._ws = ws
                    log.info("Connected to RNA broker at %s", self.broker_url)
                    await self._hello(ws)
                    async for raw in ws:
                        await self._dispatch(raw)
            except Exception as exc:
                log.warning("RNA bus disconnected (%s), retrying in 5s...", exc)
                await asyncio.sleep(5)

    async def _hello(self, ws) -> None:
        current_hlc = self.clock.current
        msg = BusMessage(
            type=BusMessageType.HELLO,
            node_id=self.node_id,
            payload={"hlc": current_hlc.to_dict()},
        )
        await ws.send(orjson.dumps(msg.model_dump()).decode())

    async def _dispatch(self, raw: str | bytes) -> None:
        msg = BusMessage.model_validate(orjson.loads(raw))

        if msg.type == BusMessageType.DELTA:
            mutations = [
                Mutation.model_validate(m) for m in msg.payload.get("mutations", [])
            ]
            applied = await self.ledger.merge_delta(mutations)
            if applied:
                log.info("RNA bus: applied %d new mutations from delta", applied)

        elif msg.type == BusMessageType.BROADCAST:
            try:
                mut = Mutation.model_validate(msg.payload["mutation"])
                # Advance our HLC
                self.clock.recv(mut.hlc.to_hlc())
                await self.ledger.merge_delta([mut])
                log.info("RNA bus: broadcast mutation applied (%s)", mut.id[:8])
            except Exception as exc:
                log.warning("Malformed broadcast: %s", exc)

    async def push(self, mutation: Mutation) -> None:
        """Push a locally derived mutation to the broker."""
        if self._ws is None:
            return
        msg = BusMessage(
            type=BusMessageType.PUSH,
            node_id=self.node_id,
            payload={"mutation": mutation.model_dump()},
        )
        try:
            await self._ws.send(orjson.dumps(msg.model_dump()).decode())
        except Exception as exc:
            log.warning("Failed to push mutation to broker: %s", exc)

    async def disconnect(self) -> None:
        self._running = False
        if self._ws:
            await self._ws.close()
