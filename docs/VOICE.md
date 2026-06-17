# Okto anti-slop voice guide

Okto copy should sound like a sharp infrastructure tool, not a generic AI wrapper.

## Voice

- **Concrete:** name the byte, stream, proxy, replay, mutation, or risk.
- **Calm:** confident without yelling.
- **Technical:** assume the reader knows agent CLIs and provider APIs.
- **Useful:** every sentence should explain behavior, setup, or why it matters.
- **Honest:** say alpha, local MITM, session capture, and CA trust plainly.

## Avoid

- “Revolutionary”, “game-changing”, “AI-powered magic”, “10x”, “seamless” unless describing an actual loop.
- Abstract claims like “unlock productivity” or “transform workflows”.
- Mascot/octopus/DNA metaphors in launch copy.
- Pretending the proxy is invisible from a security standpoint. It is powerful because it intercepts traffic; say that.

## Preferred phrases

- “raw stream frames”
- “malformed SSE chunks”
- “local HTTPS proxy”
- “repair mutation”
- “captured session replay”
- “distributed mutation genome”
- “provider drift”
- “agent protocol failures”

## One-liner

Okto is a self-healing local proxy that catches malformed AI provider streams, repairs repeat failures, and syncs the fix across your agent fleet.

## Short description

Okto sits between your agent CLI and the provider API. It records raw stream frames, detects malformed chunks, derives repair rules, and replays sessions so protocol failures become regression tests instead of mysteries.

## Long description

AI agents often fail because the protocol underneath them shifted: a malformed SSE frame, a truncated response, a provider-specific header, or a rare JSON shape the SDK hides. Okto runs as a local HTTPS proxy for agent CLIs. It captures the raw exchange, highlights anomalies in a live inspector, derives patch rules for repeat failures, and can sync those mutations over a broker so one machine’s fix becomes available to the rest of the team.

## Taglines

- Self-healing traffic for AI agents.
- Catch the broken stream before your agent does.
- Turn provider drift into replayable tests.
- A local protocol immune system for agent CLIs.
- Watch, patch, replay, sync.

## GitHub repo description

Self-healing local proxy for AI agent traffic: inspect raw streams, repair malformed SSE chunks, replay sessions, and sync protocol fixes.
