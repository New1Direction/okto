# Okto

> A self-healing local proxy for AI coding agents.

Okto sits between an agent CLI and its AI provider. It captures raw HTTP/SSE traffic, spots malformed stream frames, repairs them before the agent sees them, and stores successful fixes in a local mutation genome that can sync across a team.

**Status:** alpha. Run it only on systems and accounts you control. Okto can observe provider traffic and may capture sensitive session data.

## Why it exists

Agent failures are often protocol failures: a missing SSE prefix, truncated chunk, provider drift, SDK mismatch, bad retry header, or response shape that appears once in fifty runs. Client libraries usually hide those bytes. Okto shows them, replays them, and can patch repeat failures automatically.

## What it does

- **Intercepts agent traffic** through a local HTTPS proxy.
- **Detects stream anomalies** at the raw chunk level.
- **Derives repair mutations** for recurring protocol breaks.
- **Replays captured sessions** against the current genome.
- **Fabricates chaos sessions** for regression testing.
- **Syncs fixes over the RNA bus** so one machine can teach the rest.
- **Opens a live Traffic Inspector** for sessions, chunks, mutations, and replay.

Supported agent clients: `claude`, `gemini`, `codex`, `agy`, `kimi`, `kimi-code`, `cursor`, `opencode`, `pi`, and `hermes`.

## Install

From a checkout:

```bash
uv tool install .
# or, for development
uv sync --all-extras --dev
```

After release:

```bash
pip install okto
```

## Quick start

```bash
# Run the local proxy for Claude. The dashboard opens by default.
okto run --client claude

# Forward arguments to an agent CLI.
okto run --client gemini -- -p "hello"

# Generate a chaos session.
okto fabricate --scenario stream_mid_truncation --client claude

# Start the RNA broker for multi-node mutation sharing.
okto broker

# Connect a proxy to the broker.
okto run --client claude --broker ws://localhost:9373

# Inspect the local genome.
okto genome list
```

Dashboard default: <http://127.0.0.1:7878>

## TLS and privacy

Okto creates a local CA in `~/.okto/certs` so it can inspect HTTPS traffic from child agent processes. The `run` command sets `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE`, and `REQUESTS_CA_BUNDLE` for the launched process.

Captured sessions are stored in `~/.okto/sessions` unless `--session-dir` is provided. Review and redact captures before sharing.

On macOS, trust the local CA with:

```bash
okto ca show
okto ca trust
```

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) — install, run, dashboard, captures, genome, RNA bus.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — proxy, viewer, camouflage, ledger, security boundaries.
- [`docs/VOICE.md`](docs/VOICE.md) — anti-slop copy rules and canonical descriptions.
- [`docs/LAUNCH_COPY.md`](docs/LAUNCH_COPY.md) — GitHub/social/demo copy.
- [`docs/GITHUB_SETUP.md`](docs/GITHUB_SETUP.md) — repository description, topics, Pages setup, release notes.

## Development

```bash
uv sync --all-extras --dev
uv run ruff check .
uv run pytest -q
uv run okto --help
uv build
```

## Repository hygiene

Do not commit API keys, local CA material, captured sessions, binaries, generated videos, or reverse-engineering scratch files. See `SECURITY.md` and `CONTRIBUTING.md`.

## License

MIT © ares
