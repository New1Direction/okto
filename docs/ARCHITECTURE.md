# Okto architecture

Okto has three layers: proxy, camouflage, and RNA bus.

## 1. Self-patching proxy

The proxy is implemented in `selfhswarm/proxy/`.

- `addon.py` runs the local HTTP/HTTPS proxy.
- `tls.py` creates the local CA and per-host certificates.
- `state_machine.py` detects malformed chunks and derives repair mutations.

For HTTPS traffic, Okto handles `CONNECT`, upgrades the client socket with a locally signed certificate, opens an upstream TLS connection, and forwards HTTP/1.1 request/response data while inspecting stream chunks.

The proxy writes captured sessions to `~/.okto/sessions` by default.

## 2. Traffic Inspector

The dashboard is implemented in `selfhswarm/viewer/`.

- `server.py` exposes REST endpoints and the dashboard HTML.
- `events.py` provides the in-process event bus.
- `static/index.html` is the dashboard UI.

Important endpoints:

- `GET /` — dashboard
- `GET /api/sessions` — session list
- `GET /api/sessions/{id}` — full session detail
- `POST /api/sessions/{id}/replay` — replay captured chunks through the current genome
- `GET /api/genome` — current mutation list
- `WS /ws/live` — live event stream

## 3. Camouflage engine

The camouflage engine is implemented in `selfhswarm/camouflage/fabricator.py`.

It creates synthetic sessions that mimic real agent traffic but contain controlled failures:

- truncated streams,
- provider model swaps,
- reflection loops,
- fake IAM denials,
- inflated context,
- hallucinated tool results.

This lets you build regression fixtures for agent protocol handling.

## 4. RNA bus

The RNA bus is implemented in `selfhswarm/rna_bus/`.

- `ledger.py` stores mutations in an append-only JSONL genome.
- `broker.py` provides a WebSocket hub for sharing mutations.

Each mutation is stamped with a hybrid logical clock so nodes can order and merge repair rules.

## Data model

Core Pydantic models live in `selfhswarm/models.py`:

- `Session`
- `Turn`
- `StreamChunk`
- `Mutation`
- `Genome`
- `BusMessage`
- `LiveEvent`

## Security boundaries

Okto is intentionally powerful: it intercepts local agent traffic. Treat these as sensitive:

- local CA key material,
- captured session JSONL,
- raw request/response chunks,
- mutation logs that may include byte patterns from real provider traffic.

Do not commit or share captured sessions without review.
