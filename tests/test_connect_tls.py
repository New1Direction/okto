"""
Integration tests for the full TLS MITM CONNECT path.

These tests spin up:
  - A real asyncio HTTPS echo server (self-signed cert, acting as upstream)
  - The SelfHSwarmProxy listening on a local port
  - A plain HTTP client that sends a CONNECT request then speaks TLS

The test verifies end-to-end:
  CONNECT issued → 200 received → TLS handshake → HTTP/1.1 request
  → upstream → response chunks → through ProxyStateMachine → client.

No external network calls are made.
"""

from __future__ import annotations

import asyncio
import ssl
import tempfile
import pathlib

import pytest

from selfhswarm.hlc import HLCClock
from selfhswarm.models import AgentClient
from selfhswarm.proxy.addon import (
    SelfHSwarmProxy,
    _read_headers,
    _content_length,
    _is_streaming_response,
    _try_parse_json,
)
from selfhswarm.proxy.tls import CertAuthority
from selfhswarm.rna_bus.ledger import GenomeLedger


# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


def _free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _make_proxy(tmp_dir: str) -> tuple[SelfHSwarmProxy, int]:
    node_id = "test-node"
    clock = HLCClock(node_id)
    ledger = await GenomeLedger.load(node_id, pathlib.Path(tmp_dir) / "genome.jsonl")
    proxy = SelfHSwarmProxy(
        client=AgentClient.CLAUDE,
        upstream=None,
        ledger=ledger,
        clock=clock,
        session_dir=tmp_dir,
    )
    port = _free_port()
    await proxy.start("127.0.0.1", port)
    return proxy, port


# ---------------------------------------------------------------------------
# Unit tests for HTTP parsing helpers
# ---------------------------------------------------------------------------


class TestHttpHelpers:
    async def test_read_headers_basic(self):
        data = b"Content-Type: application/json\r\nAccept: */*\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        headers = await _read_headers(reader)
        assert headers["content-type"] == "application/json"
        assert headers["accept"] == "*/*"

    async def test_read_headers_empty(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\r\n")
        reader.feed_eof()
        headers = await _read_headers(reader)
        assert headers == {}

    def test_is_streaming_response_sse(self):
        assert _is_streaming_response({"content-type": "text/event-stream"})

    def test_is_streaming_response_chunked(self):
        assert _is_streaming_response({"transfer-encoding": "chunked"})

    def test_is_streaming_response_false(self):
        assert not _is_streaming_response({"content-type": "application/json"})

    def test_content_length(self):
        assert _content_length({"content-length": "42"}) == 42
        assert _content_length({}) == 0
        assert _content_length({"content-length": "abc"}) == 0

    def test_try_parse_json(self):
        assert _try_parse_json(b'{"a": 1}') == {"a": 1}
        assert _try_parse_json(b"bad json") is None
        assert _try_parse_json(b"") is None


# ---------------------------------------------------------------------------
# CONNECT tunnel unit test (mocked upstream)
# ---------------------------------------------------------------------------


class TestConnectParsing:
    """Test the CONNECT request parsing without live TLS."""

    async def test_handle_connect_bad_request(self):
        """Malformed CONNECT should return 400 without crashing."""
        with tempfile.TemporaryDirectory() as tmp:
            proxy, port = await _make_proxy(tmp)

            reader = asyncio.StreamReader()
            # Send a badly-formed first line
            reader.feed_data(b"CONNECT \r\n\r\n")  # no host
            reader.feed_eof()

            output = bytearray()

            class _MockWriter:
                _transport = None

                def write(self, data: bytes) -> None:
                    output.extend(data)

                async def drain(self) -> None:
                    pass

                def close(self) -> None:
                    pass

                async def wait_closed(self) -> None:
                    pass

                def get_extra_info(self, key, default=None):
                    return default

            mock_writer = _MockWriter()

            # Should not raise; returns after writing 400
            await proxy._handle_connect(reader, mock_writer, b"CONNECT \r\n")
            # 400 written means parsing failed gracefully
            assert b"400" in bytes(output)

            await proxy.stop()


# ---------------------------------------------------------------------------
# End-to-end HTTPS interception test
# ---------------------------------------------------------------------------


@pytest.fixture
def ca():
    with tempfile.TemporaryDirectory() as d:
        yield CertAuthority(pathlib.Path(d) / "certs")


class TestTLSMITM:
    """
    Spin up a minimal HTTPS echo server, proxy a CONNECT through selfhswarm,
    and verify the response arrives mutated correctly.
    """

    async def test_full_connect_tls_roundtrip(self, ca):
        """
        End-to-end:
          client → proxy CONNECT → TLS upgrade → upstream HTTPS echo → back
        """
        # ── 1. Upstream echo server ─────────────────────────────────────
        upstream_port = _free_port()
        proxy_port = _free_port()

        # The upstream uses a real cert from our test CA
        upstream_ctx = ca.server_context("127.0.0.1")

        body_to_send = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hello\"}}\n\n"

        async def echo_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter):
            """Minimal HTTPS server: read any request, return SSE body."""
            # Read request headers
            await r.readline()          # request line
            while True:
                line = await r.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            # Write SSE response
            w.write(b"HTTP/1.1 200 OK\r\n")
            w.write(b"Content-Type: text/event-stream\r\n")
            w.write(b"\r\n")
            w.write(body_to_send)
            await w.drain()
            w.close()

        upstream_server = await asyncio.start_server(
            echo_handler, "127.0.0.1", upstream_port, ssl=upstream_ctx
        )

        # ── 2. Selfhswarm proxy ─────────────────────────────────────────
        with tempfile.TemporaryDirectory() as tmp:
            node_id = "e2e-test"
            clock = HLCClock(node_id)
            ledger = await GenomeLedger.load(
                node_id, pathlib.Path(tmp) / "genome.jsonl"
            )
            # The upstream echo server uses ca's self-signed cert.
            # Teach the proxy to trust it when connecting upstream.
            upstream_ssl = ssl.create_default_context()
            upstream_ssl.load_verify_locations(str(ca.ca_cert_path))

            proxy = SelfHSwarmProxy(
                client=AgentClient.CLAUDE,
                upstream=f"https://127.0.0.1:{upstream_port}",
                ledger=ledger,
                clock=clock,
                session_dir=tmp,
                upstream_ssl=upstream_ssl,
            )
            await proxy.start("127.0.0.1", proxy_port)

            # ── 3. Client: send CONNECT then HTTP request ───────────────
            # Use the proxy CA as the trusted root so the client trusts the
            # forged leaf cert presented by the proxy.
            client_trust_ctx = ssl.create_default_context()
            client_trust_ctx.load_verify_locations(str(proxy._ca.ca_cert_path))

            # Open plain TCP to proxy
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)

            # Send CONNECT
            w.write(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n" % upstream_port)
            await w.drain()

            # Read 200 Connection Established
            status_line = await r.readline()
            assert b"200" in status_line, f"Expected 200, got {status_line!r}"
            # Drain blank line
            await _read_headers(r)

            # ── 4. Upgrade to TLS (client side) ────────────────────────
            await w.start_tls(client_trust_ctx, server_hostname="127.0.0.1")

            # ── 5. Send HTTP request through the tunnel ─────────────────
            w.write(b"GET /v1/messages HTTP/1.1\r\n")
            w.write(b"Host: 127.0.0.1\r\n")
            w.write(b"Connection: close\r\n")
            w.write(b"\r\n")
            await w.drain()

            # ── 6. Read full response ───────────────────────────────────
            response_bytes = b""
            while True:
                chunk = await asyncio.wait_for(r.read(4096), timeout=5.0)
                if not chunk:
                    break
                response_bytes += chunk

            w.close()
            await proxy.stop()
            upstream_server.close()

        # ── 7. Assertions ───────────────────────────────────────────────
        assert b"200 OK" in response_bytes, f"No 200 in: {response_bytes!r}"
        # The SSE body must have passed through the proxy
        assert b"content_block_delta" in response_bytes, (
            f"SSE payload not found in: {response_bytes!r}"
        )

    async def test_state_machine_fires_during_connect(self, ca):
        """
        Anomalous upstream response should trigger state machine.
        Verify session is recorded with anomaly metadata.
        """
        upstream_port = _free_port()
        proxy_port = _free_port()

        upstream_ctx = ca.server_context("127.0.0.1")

        # Upstream sends a bare JSON object WITHOUT the required 'data:' SSE prefix
        # → this triggers the SSE prefix anomaly detector in the state machine
        anomalous_body = b'{"type":"content_block_delta","bare":true}\n\n'

        async def anomalous_handler(r, w):
            while True:
                line = await r.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            w.write(b"HTTP/1.1 200 OK\r\n")
            w.write(b"Content-Type: text/event-stream\r\n")
            w.write(b"\r\n")
            w.write(anomalous_body)
            await w.drain()
            w.close()

        upstream_server = await asyncio.start_server(
            anomalous_handler, "127.0.0.1", upstream_port, ssl=upstream_ctx
        )

        with tempfile.TemporaryDirectory() as tmp:
            node_id = "anomaly-test"
            clock = HLCClock(node_id)
            ledger = await GenomeLedger.load(
                node_id, pathlib.Path(tmp) / "genome.jsonl"
            )
            upstream_ssl = ssl.create_default_context()
            upstream_ssl.load_verify_locations(str(ca.ca_cert_path))

            proxy = SelfHSwarmProxy(
                client=AgentClient.CLAUDE,
                upstream=f"https://127.0.0.1:{upstream_port}",
                ledger=ledger,
                clock=clock,
                session_dir=tmp,
                upstream_ssl=upstream_ssl,
            )
            await proxy.start("127.0.0.1", proxy_port)

            client_trust_ctx = ssl.create_default_context()
            client_trust_ctx.load_verify_locations(str(proxy._ca.ca_cert_path))

            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
            w.write(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n" % upstream_port)
            await w.drain()
            await r.readline()          # 200 line
            await _read_headers(r)      # blank

            await w.start_tls(client_trust_ctx, server_hostname="127.0.0.1")
            w.write(b"GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            await w.drain()

            # Drain response
            while True:
                chunk = await asyncio.wait_for(r.read(4096), timeout=5.0)
                if not chunk:
                    break

            w.close()
            await asyncio.sleep(0.1)  # let session persist

            # Verify genome gained a new mutation from the anomaly
            assert len(ledger.genome.mutations) > 0, (
                "Expected at least one derived mutation after anomalous SSE"
            )

            await proxy.stop()
            upstream_server.close()
