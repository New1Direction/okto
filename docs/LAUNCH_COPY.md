# Okto launch copy

## GitHub about

**Description**

Self-healing local proxy for AI agent traffic: inspect raw streams, repair malformed SSE chunks, replay sessions, and sync protocol fixes.

**Topics**

`ai-agents`, `proxy`, `sse`, `llm`, `debugging`, `chaos-engineering`, `fastapi`, `python`, `protocols`, `agent-tools`

## README hero

Okto sits between an agent CLI and its AI provider. It captures raw HTTP/SSE traffic, spots malformed stream frames, repairs them before the agent sees them, and stores successful fixes in a local mutation genome that can sync across a team.

## Product Hunt / short launch

Agent failures are often protocol failures: malformed SSE chunks, truncated streams, provider drift, and rare response shapes hidden by SDKs. Okto runs as a local HTTPS proxy for agent CLIs, shows the raw bytes, replays captured sessions, and learns repair mutations for repeat failures.

## Hacker News title options

- Show HN: Okto – a self-healing local proxy for AI agent traffic
- Show HN: I built a proxy that catches malformed LLM streams before agents crash
- Show HN: Turn AI provider stream bugs into replayable tests

## X / social posts

**Short**

Built Okto: a local HTTPS proxy for AI agent CLIs. It captures raw provider streams, spots malformed SSE chunks, replays broken sessions, and learns repair rules for repeat failures.

**Launch thread opener**

AI agents do not only fail because the model is wrong. They fail because the stream underneath them gets weird: truncated chunks, malformed SSE, provider drift, undocumented response shapes. Okto is a local proxy that makes those failures visible and replayable.

**Builder-focused**

If you run agent CLIs in production-like workflows, you need to see the wire. Okto captures the raw exchange, flags malformed chunks, opens a live traffic inspector, and turns protocol weirdness into regression fixtures.

## Demo script

1. Start the proxy:

   ```bash
   okto run --client claude
   ```

2. Open the Traffic Inspector at `http://127.0.0.1:7878`.
3. Run an agent prompt through the proxy.
4. Show the captured session, raw chunks, provider profile, and replay controls.
5. Generate a failure fixture:

   ```bash
   okto fabricate --scenario stream_mid_truncation --client claude
   ```

6. Show `okto genome list` and explain that learned repairs can sync over the RNA bus.

## Demo caveat

Okto is alpha and intercepts HTTPS traffic from child agent processes. Use it only on systems and accounts you control. Review captured sessions before sharing.
