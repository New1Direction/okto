"""
Layer 1 — raw-asyncio forward proxy with full TLS MITM.

Architecture
────────────
  asyncio.start_server → _accept()
    ├── CONNECT request  → _handle_connect()   (TLS MITM path)
    │     ├─ forge leaf cert (tls.py LRU cache)
    │     ├─ send 200 Connection Established
    │     ├─ StreamWriter.start_tls(server_ctx) — upgrade client socket to TLS
    │     ├─ open upstream TLS connection
    │     └─ HTTP/1.1 request-response loop, every chunk → ProxyStateMachine
    └── plain HTTP      → _handle_plain_http() (aiohttp.ClientSession forward)
          └─ every upstream chunk → ProxyStateMachine

Why asyncio.start_server instead of aiohttp.web
────────────────────────────────────────────────
aiohttp.web is a request/response framework; it buffers the full body
before calling the handler and does not expose the raw asyncio transport.
Upgrading the underlying socket to TLS (asyncio.start_tls) requires
access to the Protocol object and the transport, which are only available
at the asyncio.Protocol / asyncio.StreamWriter level.

Key: StreamWriter.start_tls() in Python 3.11+
────────────────────────────────────────────────
When the writer was produced by asyncio.start_server, the backing
StreamReaderProtocol._client_connected_cb is non-None → start_tls()
automatically sets server_side=True.  After awaiting start_tls(), both
the writer and the shared reader are transparently upgraded; the
StreamReader continues receiving data via the protocol's data_received().
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import ssl
import time
import uuid
from typing import TYPE_CHECKING

import orjson
from aiohttp import ClientSession, TCPConnector

from selfhswarm.hlc import HLCClock
from selfhswarm.models import (
    AgentClient,
    HLCModel,
    LiveEvent,
    LiveEventType,
    Mutation,
    MutationScope,
    Session,
    StreamChunk,
    Turn,
    detect_provider,
)
from selfhswarm.proxy.state_machine import ProxyStateMachine
from selfhswarm.proxy.tls import CertAuthority

if TYPE_CHECKING:
    from selfhswarm.rna_bus.ledger import GenomeLedger
    from selfhswarm.viewer.events import EventBus

log = logging.getLogger(__name__)

# How many bytes to read per chunk from the upstream response stream.
_CHUNK_SIZE = 4096

# Seconds to wait for the client to send the first byte.
_ACCEPT_TIMEOUT = 15.0

# Seconds to wait for the next HTTP request on a keep-alive CONNECT tunnel.
_KEEPALIVE_TIMEOUT = 60.0


# ---------------------------------------------------------------------------
# Upstream target registry
# ---------------------------------------------------------------------------

UPSTREAM_DEFAULTS: dict[AgentClient, str] = {
    AgentClient.CLAUDE:    "https://api.anthropic.com",
    AgentClient.GEMINI:    "https://generativelanguage.googleapis.com",
    AgentClient.CODEX:     "https://api.openai.com",
    AgentClient.AGY:       "https://autopilot.googleapis.com",
    AgentClient.KIMI:      "https://api.moonshot.ai",
    AgentClient.KIMI_CODE: "https://api.moonshot.ai",
    AgentClient.CURSOR:    "https://api2.cursor.sh",
    AgentClient.OPENCODE:  "https://api.openai.com",
    AgentClient.PI:        "https://api.openai.com",
    AgentClient.HERMES:    "https://api.openai.com",
    AgentClient.UNKNOWN:   "https://api.anthropic.com",
}


# ---------------------------------------------------------------------------
# HTTP/1.1 parsing helpers (minimal, no third-party deps)
# ---------------------------------------------------------------------------


async def _read_headers(reader: asyncio.StreamReader) -> dict[str, str]:
    """Read HTTP headers until the blank line. Returns lowercase-keyed dict."""
    headers: dict[str, str] = {}
    while True:
        raw = await reader.readline()
        if raw in (b"\r\n", b"\n", b""):
            break
        if b":" in raw:
            key, _, val = raw.partition(b":")
            headers[key.strip().lower().decode("latin-1")] = val.strip().decode("latin-1")
    return headers


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
    """
    Read a request body based on Content-Length.

    Chunked request bodies are not common from LLM clients (they send
    a JSON payload with a known length), so we only handle Content-Length.
    """
    cl = headers.get("content-length")
    if cl and cl.isdigit():
        n = int(cl)
        if n > 0:
            return await reader.readexactly(n)
    return b""


def _is_streaming_response(resp_headers: dict[str, str]) -> bool:
    """True if the upstream response is an SSE or chunked stream."""
    ct = resp_headers.get("content-type", "")
    te = resp_headers.get("transfer-encoding", "")
    return "text/event-stream" in ct or "chunked" in te


def _serialise_headers(headers: dict[str, str]) -> bytes:
    """Encode a header dict back to HTTP/1.1 wire format."""
    return b"".join(
        f"{k}: {v}\r\n".encode("latin-1") for k, v in headers.items()
    )


# ---------------------------------------------------------------------------
# Main proxy class
# ---------------------------------------------------------------------------


class SelfHSwarmProxy:
    """
    Self-patching asyncio forward proxy.

    One instance per process.  Each inbound TCP connection gets its own
    asyncio task running _accept(), which dispatches to either the full
    TLS MITM path or the plain HTTP path.
    """

    def __init__(
        self,
        client: AgentClient,
        upstream: str | None,
        ledger: GenomeLedger,
        clock: HLCClock,
        session_dir: str,
        upstream_ssl: ssl.SSLContext | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self.client = client
        self.upstream = (
            upstream
            or UPSTREAM_DEFAULTS.get(client, UPSTREAM_DEFAULTS[AgentClient.CLAUDE])
        )
        self.ledger = ledger
        self.clock = clock
        self.session_dir = session_dir
        # If None, ssl.create_default_context() is used per connection.
        # Tests inject a context that trusts their local CA.
        self._upstream_ssl = upstream_ssl
        self._event_bus = event_bus
        self._ca = CertAuthority()
        # aiohttp ClientSession used only for plain-HTTP forwarding
        self._http_session: ClientSession | None = None
        self._server: asyncio.Server | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, host: str = "127.0.0.1", port: int = 8877) -> None:
        connector = TCPConnector(ssl=False, limit=200)
        self._http_session = ClientSession(connector=connector)
        self._server = await asyncio.start_server(
            self._accept, host, port, limit=2**20  # 1 MiB stream buffer
        )
        log.info("Okto proxy listening on %s:%s", host, port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._http_session:
            await self._http_session.close()

    # ------------------------------------------------------------------
    # Connection dispatcher
    # ------------------------------------------------------------------

    async def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Entry point for every inbound TCP connection."""
        peer = writer.get_extra_info("peername", "<unknown>")
        try:
            first_line = await asyncio.wait_for(
                reader.readline(), timeout=_ACCEPT_TIMEOUT
            )
        except (TimeoutError, ConnectionError):
            writer.close()
            return

        if not first_line:
            writer.close()
            return

        try:
            if first_line.upper().startswith(b"CONNECT "):
                await self._handle_connect(reader, writer, first_line)
            else:
                await self._handle_plain_http(reader, writer, first_line)
        except Exception as exc:
            log.debug("Connection from %s closed: %s", peer, exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # CONNECT path — full TLS MITM
    # ------------------------------------------------------------------

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_line: bytes,
    ) -> None:
        """
        Handle an HTTP CONNECT tunnel with full TLS interception.

        Sequence
        ────────
        1.  Parse  CONNECT api.anthropic.com:443 HTTP/1.1
        2.  Drain remaining request headers (no body on CONNECT)
        3.  Send   HTTP/1.1 200 Connection established
        4.  Upgrade client socket to server-side TLS using the forged cert
              await writer.start_tls(server_ctx)
              ↳  sets server_side=True because this writer was produced
                 by asyncio.start_server (_client_connected_cb is non-None)
              ↳  reader continues to work — data_received() on the shared
                 StreamReaderProtocol feeds the reader's internal buffer
        5.  Open upstream TLS connection
        6.  Run the HTTP/1.1 request-response loop:
              for each turn:
                a. read decrypted request from client
                b. optionally mutate request body through state machine
                c. forward to upstream
                d. read upstream response status + headers
                e. stream response body chunks through state machine
                f. forward (possibly rewritten) chunks to client
                g. record turn in Session, persist JSONL
        """
        # ── 1. Parse target host:port ────────────────────────────────
        try:
            parts = first_line.split()
            # parts = [b'CONNECT', b'api.anthropic.com:443', b'HTTP/1.1']
            host_port = parts[1].decode("ascii")
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_port
                port = 443
        except Exception:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return

        log.debug("CONNECT %s:%s", host, port)

        # ── 2. Drain CONNECT headers ─────────────────────────────────
        await _read_headers(reader)

        # ── 3. Send 200 Connection Established ──────────────────────
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        # ── 4. Upgrade client connection to server-side TLS ──────────
        #
        # CertAuthority.server_context() returns an ssl.SSLContext with
        # a leaf cert signed by our local CA, minted for this hostname.
        # The LRU cache in tls.py ensures we generate at most once per host.
        #
        # writer.start_tls() (Python 3.11+):
        #   - Calls loop.start_tls(transport, protocol, ctx, server_side=True)
        #   - Performs the TLS handshake with the client
        #   - Updates writer._transport to the new SSLTransport in-place
        #   - The reader continues to work: data_received() is still called
        #     on the StreamReaderProtocol which feeds reader._buffer
        server_ctx = self._ca.server_context(host)
        try:
            await writer.start_tls(server_ctx)
        except ssl.SSLError as exc:
            log.warning("TLS handshake failed for %s: %s", host, exc)
            return

        # ── 5. Open upstream TLS connection ──────────────────────────
        upstream_ssl = self._upstream_ssl or ssl.create_default_context()
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                host, port, ssl=upstream_ssl, server_hostname=host
            )
        except Exception as exc:
            log.error("Failed to connect to upstream %s:%s — %s", host, port, exc)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return

        # ── 6. HTTP/1.1 request-response loop ────────────────────────
        session_id = str(uuid.uuid4())
        provider  = detect_provider(host)
        session = Session(
            id=session_id,
            client=self.client,
            node_id=self.clock.node_id,
            started_at_hlc=HLCModel.from_hlc(self.clock.tick()),
            connect_target=f"{host}:{port}",
            tls_established=True,
            provider=provider,
        )
        await self._emit(LiveEvent(
            type=LiveEventType.SESSION_START,
            session_id=session_id,
            payload={
                "connect_target": f"{host}:{port}",
                "tls_established": True,
                "provider": provider.model_dump(),
                "client": self.client.value,
            },
        ))
        sm = self._make_state_machine(session_id)

        try:
            await self._http_loop(
                client_reader=reader,
                client_writer=writer,
                upstream_reader=upstream_reader,
                upstream_writer=upstream_writer,
                session=session,
                sm=sm,
                tls_host=host,
            )
        finally:
            try:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            except Exception:
                pass
            await self._persist_session(session)
            await self._emit(LiveEvent(
                type=LiveEventType.SESSION_END,
                session_id=session_id,
                payload={"turn_count": len(session.turns)},
            ))
            log.debug(
                "Session %s: %d turns, %d upstream anomalies",
                session_id[:8],
                len(session.turns),
                sum(t.anomalies_detected for t in session.turns),
            )

    async def _http_loop(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        session: Session,
        sm: ProxyStateMachine,
        tls_host: str,
    ) -> None:
        """
        Drive one HTTP/1.1 keep-alive conversation over a CONNECT tunnel.

        Each iteration of the while loop is one request–response pair (Turn).
        The loop exits when:
          - the client closes the connection (readline returns b"")
          - the upstream closes the connection
          - Connection: close is signalled by either side
          - a timeout elapses waiting for the next request
        """
        while True:
            # ── a. Read request line (with keep-alive timeout) ───────
            try:
                req_line = await asyncio.wait_for(
                    client_reader.readline(), timeout=_KEEPALIVE_TIMEOUT
                )
            except TimeoutError:
                break
            if not req_line or req_line == b"\r\n":
                break

            # ── b. Read request headers + body ───────────────────────
            req_headers = await _read_headers(client_reader)
            req_body = await _read_body(client_reader, req_headers)

            # Strip proxy-specific headers before forwarding
            req_headers.pop("proxy-connection", None)
            req_headers.pop("proxy-authorization", None)

            # Run request body through state machine (REQUEST_BODY scope)
            req_body_out = req_body
            req_body_chunk_meta: StreamChunk | None = None
            if req_body:
                req_body_out, req_body_chunk_meta = sm.process_chunk(
                    req_body, MutationScope.REQUEST_BODY
                )

            # ── c. Forward request to upstream ───────────────────────
            upstream_writer.write(req_line)
            upstream_writer.write(_serialise_headers(req_headers))
            upstream_writer.write(b"\r\n")
            if req_body_out:
                upstream_writer.write(req_body_out)
            await upstream_writer.drain()

            t_start = time.monotonic()

            # ── d. Read upstream response status + headers ────────────
            try:
                resp_status_line = await upstream_reader.readline()
            except Exception:
                break
            if not resp_status_line:
                break
            resp_headers = await _read_headers(upstream_reader)

            # Parse status code
            try:
                status_code = int(resp_status_line.split()[1])
            except (IndexError, ValueError):
                status_code = 200

            # Build Turn record
            turn = Turn(
                index=len(session.turns),
                request_headers=req_headers,
                request_body=_try_parse_json(req_body),
                response_headers=resp_headers,
                response_status=status_code,
            )
            if req_body_chunk_meta:
                turn.stream_chunks.append(req_body_chunk_meta)

            # ── e+f. Stream response body through state machine ───────
            #
            # Forward response status + headers to client first, then stream
            # the body chunk-by-chunk so the client can start rendering
            # (critical for SSE where the first token can arrive immediately).
            client_writer.write(resp_status_line)
            client_writer.write(_serialise_headers(resp_headers))
            client_writer.write(b"\r\n")
            await client_writer.drain()

            streaming = _is_streaming_response(resp_headers)
            content_length = _content_length(resp_headers)

            if streaming:
                await self._stream_chunked_response(
                    upstream_reader, client_writer, sm, turn, session.id
                )
            elif content_length > 0:
                await self._stream_fixed_response(
                    upstream_reader, client_writer, sm, turn, content_length, session.id
                )
            # else: no body (e.g. 204 No Content)

            turn.duration_ms = (time.monotonic() - t_start) * 1000
            session.turns.append(turn)

            # Emit turn_complete event (include anomalous chunks for dashboard)
            anomalous_chunks = [
                {
                    "index": c.index,
                    "raw_hex": c.raw_hex,
                    "anomaly_type": c.anomaly_type,
                    "expected_hex": c.expected_hex,
                    "applied_mutation_id": c.applied_mutation_id,
                }
                for c in turn.stream_chunks
                if c.anomalous
            ]
            req_parts = req_line.split() if req_line else []
            await self._emit(
                LiveEvent(
                    type=LiveEventType.TURN_COMPLETE,
                    session_id=session.id,
                    payload={
                        "turn_index": turn.index,
                        "method": req_parts[0].decode("latin-1") if req_parts else "POST",
                        "path": req_parts[1].decode("latin-1") if len(req_parts) > 1 else "/",
                        "status_code": status_code,
                        "duration_ms": turn.duration_ms,
                        "chunk_count": len(turn.stream_chunks),
                        "anomaly_count": turn.anomalies_detected,
                        "chunks": anomalous_chunks,
                    },
                )
            )

            # ── g. Keep-alive check ───────────────────────────────────
            conn_client = req_headers.get("connection", "").lower()
            conn_server = resp_headers.get("connection", "").lower()
            if "close" in (conn_client, conn_server):
                break

    async def _stream_chunked_response(
        self,
        upstream_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        sm: ProxyStateMachine,
        turn: Turn,
        session_id: str = "",
    ) -> None:
        """
        Stream an SSE or Transfer-Encoding: chunked response.

        Reads TCP chunks of up to _CHUNK_SIZE bytes from upstream, runs
        each through the ProxyStateMachine, then writes the (possibly
        rewritten) bytes to the client.

        The state machine operates at the chunk boundary level, not the
        SSE event boundary level.  This is intentional: anomalous bytes
        can appear mid-chunk, and the patch engine works on raw bytes.
        """
        while True:
            try:
                raw = await asyncio.wait_for(
                    upstream_reader.read(_CHUNK_SIZE), timeout=120.0
                )
            except TimeoutError:
                log.warning("Upstream stream timed out after 120s")
                break
            if not raw:
                break  # upstream closed cleanly

            rewritten, chunk_meta = sm.process_chunk(raw, MutationScope.STREAM_CHUNK)
            turn.stream_chunks.append(chunk_meta)
            if chunk_meta.anomalous:
                turn.anomalies_detected += 1
                log.debug(
                    "Anomaly in turn %d chunk %d — applied mutation: %s",
                    turn.index,
                    chunk_meta.index,
                    chunk_meta.applied_mutation_id or "none",
                )
                await self._emit(LiveEvent(
                    type=LiveEventType.ANOMALY_DETECTED,
                    session_id=session_id,
                    payload={
                        "turn_index": turn.index,
                        "chunk_index": chunk_meta.index,
                        "anomaly_type": chunk_meta.anomaly_type,
                        "raw_hex": chunk_meta.raw_hex,
                        "expected_hex": chunk_meta.expected_hex,
                    },
                ))
            if chunk_meta.applied_mutation_id:
                turn.mutations_applied.append(chunk_meta.applied_mutation_id)

            client_writer.write(rewritten)
            await client_writer.drain()

    async def _stream_fixed_response(
        self,
        upstream_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        sm: ProxyStateMachine,
        turn: Turn,
        content_length: int,
        session_id: str = "",
    ) -> None:
        """
        Stream a fixed-length response body in _CHUNK_SIZE chunks.

        Even non-streaming responses are piped chunk-by-chunk so that
        large JSON payloads are still processed by the state machine.
        """
        remaining = content_length
        while remaining > 0:
            to_read = min(_CHUNK_SIZE, remaining)
            try:
                raw = await asyncio.wait_for(
                    upstream_reader.read(to_read), timeout=60.0
                )
            except TimeoutError:
                break
            if not raw:
                break

            rewritten, chunk_meta = sm.process_chunk(raw, MutationScope.RESPONSE_BODY)
            turn.stream_chunks.append(chunk_meta)
            if chunk_meta.anomalous:
                turn.anomalies_detected += 1
            if chunk_meta.applied_mutation_id:
                turn.mutations_applied.append(chunk_meta.applied_mutation_id)

            client_writer.write(rewritten)
            await client_writer.drain()
            remaining -= len(raw)

    # ------------------------------------------------------------------
    # Plain HTTP path (no CONNECT, no TLS)
    # ------------------------------------------------------------------

    async def _handle_plain_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_line: bytes,
    ) -> None:
        """
        Forward a plain HTTP request to the configured upstream.

        Uses aiohttp.ClientSession for outbound so we get HTTP/1.1
        keep-alive connection pooling automatically.
        """
        assert self._http_session is not None

        try:
            parts = first_line.split(None, 2)
            method = parts[0].decode("ascii")
            path = parts[1].decode("ascii")
        except (IndexError, ValueError):
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return

        req_headers = await _read_headers(reader)
        req_body = await _read_body(reader, req_headers)

        req_headers.pop("proxy-connection", None)
        req_headers.pop("host", None)  # aiohttp sets this from the URL

        target_url = f"{self.upstream}{path}"
        session_id = str(uuid.uuid4())
        session = Session(
            id=session_id,
            client=self.client,
            node_id=self.clock.node_id,
            started_at_hlc=HLCModel.from_hlc(self.clock.tick()),
        )
        sm = self._make_state_machine(session_id)
        turn = Turn(
            index=0,
            request_headers=req_headers,
            request_body=_try_parse_json(req_body),
        )
        t_start = time.monotonic()

        try:
            async with self._http_session.request(
                method=method,
                url=target_url,
                headers=req_headers,
                data=req_body or None,
                allow_redirects=False,
            ) as upstream_resp:
                turn.response_status = upstream_resp.status
                turn.response_headers = {
                    k: v for k, v in upstream_resp.headers.items()
                }

                # Build and send response status + headers
                status_line = (
                    f"HTTP/1.1 {upstream_resp.status} "
                    f"{upstream_resp.reason}\r\n"
                ).encode()
                writer.write(status_line)
                # Exclude hop-by-hop headers that aiohttp already handled
                _skip = {"transfer-encoding", "content-encoding", "content-length"}
                for k, v in upstream_resp.headers.items():
                    if k.lower() not in _skip:
                        writer.write(f"{k}: {v}\r\n".encode())
                writer.write(b"\r\n")
                await writer.drain()

                # Stream body through state machine
                async for raw in upstream_resp.content.iter_chunked(_CHUNK_SIZE):
                    rewritten, chunk_meta = sm.process_chunk(
                        raw, MutationScope.STREAM_CHUNK
                    )
                    turn.stream_chunks.append(chunk_meta)
                    if chunk_meta.anomalous:
                        turn.anomalies_detected += 1
                    if chunk_meta.applied_mutation_id:
                        turn.mutations_applied.append(chunk_meta.applied_mutation_id)
                    writer.write(rewritten)
                    await writer.drain()

        except Exception as exc:
            log.error("Plain HTTP upstream failed: %s", exc)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()

        turn.duration_ms = (time.monotonic() - t_start) * 1000
        session.turns.append(turn)
        await self._persist_session(session)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_state_machine(self, session_id: str) -> ProxyStateMachine:
        async def _on_mutation(mut: Mutation) -> None:
            self.ledger.append(mut)
            await self._emit(LiveEvent(
                type=LiveEventType.MUTATION_DERIVED,
                session_id=session_id,
                payload={
                    "turn_index": 0,   # best-effort; state machine doesn't track current turn
                    "mutation": mut.model_dump(),
                },
            ))

        # The state machine's on_new_mutation is sync; wrap so we can emit
        def _on_mutation_sync(mut: Mutation) -> None:
            self.ledger.append(mut)
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._emit(LiveEvent(
                        type=LiveEventType.MUTATION_DERIVED,
                        session_id=session_id,
                        payload={"mutation": mut.model_dump()},
                    )))
            except Exception:
                pass

        return ProxyStateMachine(
            client=self.client,
            node_id=self.clock.node_id,
            session_id=session_id,
            genome_mutations=self.ledger.genome.for_client(self.client),
            clock=self.clock,
            on_new_mutation=_on_mutation_sync,
        )

    async def _persist_session(self, session: Session) -> None:
        path = pathlib.Path(self.session_dir) / f"{session.id}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            path.write_bytes,
            orjson.dumps(session.model_dump()),
        )

    async def _emit(self, event: LiveEvent) -> None:
        """Publish to the EventBus if one is attached (no-op otherwise)."""
        if self._event_bus is not None:
            await self._event_bus.publish(event)


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _try_parse_json(body: bytes) -> dict | None:
    if not body:
        return None
    try:
        return orjson.loads(body)
    except Exception:
        return None


def _content_length(headers: dict[str, str]) -> int:
    cl = headers.get("content-length", "")
    return int(cl) if cl.isdigit() else 0
