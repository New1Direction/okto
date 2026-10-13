# Okto usage guide

Okto is a local HTTPS proxy for AI agent CLIs. It captures raw provider traffic, flags malformed stream chunks, derives repair mutations, and lets you replay captured sessions.

## Install from source

```bash
uv tool install .
# or for development
uv sync --all-extras --dev
```

## Run an agent through Okto

```bash
okto run --client claude
```

Okto starts three things:

1. a local proxy on `127.0.0.1:8877`,
2. a Traffic Inspector dashboard on `127.0.0.1:7878`,
3. a child agent process if you pass arguments after `--`.

Forward arguments to the agent CLI:

```bash
okto run --client gemini -- -p "hello"
okto run --client claude -- --model claude-opus-4-6
```

## Trust the local CA

Okto generates a local certificate authority under `~/.okto/certs`.

```bash
okto ca show
okto ca trust
```

`ca trust` currently targets macOS system trust. On other systems, import the path from `okto ca show` into your OS/browser trust store manually.

## Captured data

Default paths:

- node id: `~/.okto/node_id`
- local CA: `~/.okto/certs`
- session captures: `~/.okto/sessions`
- mutation genome: `~/.okto/genome.jsonl`
- Korg export fingerprint key: `~/.okto/korg_export.key`

Captured sessions may include prompts, tool payloads, headers, and model output. Review before sharing.

## Dashboard

When `okto run` starts, open:

```text
http://127.0.0.1:7878
```

The Traffic Inspector shows:

- live sessions,
- provider profile,
- raw stream chunks,
- anomaly labels,
- mutations applied,
- replay results,
- current genome state.

## Chaos fabrication

Generate synthetic sessions for regression tests:

```bash
okto fabricate --scenario stream_mid_truncation --client claude
okto fabricate --scenario reflection_loop --client claude --output chaos.jsonl
```

Useful when you want to test an agent against malformed streams without waiting for a provider to fail in the wild.

## Genome inspection

```bash
okto genome list
okto genome clear
```

The genome is an append-only set of learned repair mutations. Clear it only when you want to reset local learning.

## Export to Korg

Write one capture as a sanitized, hash-chained Korg ledger:

```bash
okto korg export <session-id> -o session.korg.jsonl
okto korg verify session.korg.jsonl
```

The file holds turn summaries, anomaly labels, repair summaries, replay evidence against the current genome, provenance, and causal links. Headers, bodies, stream bytes, and mutation patterns are never written. Values that must be referenced are written as HMAC fingerprints under a local key. See [`KORG.md`](KORG.md) for the full contract.

## RNA bus

Run a broker:

```bash
okto broker --port 9373
```

Connect a node:

```bash
okto run --client claude --broker ws://localhost:9373
```

When one node learns a mutation, it can push the mutation to the broker. Other nodes can receive it and repair the same protocol failure later.
