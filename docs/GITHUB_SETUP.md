# GitHub setup for Okto

Use these values when creating or updating the GitHub repository.

## Repository name

```text
okto
```

## Description

```text
Self-healing local proxy for AI agent traffic: inspect raw streams, repair malformed SSE chunks, replay sessions, and sync protocol fixes.
```

## Website

If GitHub Pages is enabled from `/docs`:

```text
https://<owner>.github.io/okto/
```

## Topics

```text
ai-agents
proxy
sse
llm
debugging
chaos-engineering
fastapi
python
protocols
agent-tools
```

## Suggested first release title

```text
Okto v0.1.0 — local protocol inspector for AI agents
```

## Suggested release notes

```markdown
Initial alpha release of Okto.

Okto is a local HTTPS proxy for AI agent CLIs. It captures raw provider streams, detects malformed chunks, replays sessions, and stores repair mutations that can sync across a team.

### Included

- Local proxy for supported agent CLIs
- TLS interception with local CA
- Live Traffic Inspector dashboard
- Session capture and replay
- Chaos session fabricator
- Append-only mutation genome
- RNA bus WebSocket broker
- GitHub Pages docs site

### Warning

Okto intercepts HTTPS traffic from child agent processes and stores local session captures. Use it only on systems and accounts you control. Review captures before sharing.
```

## Pages

For the current static site, configure GitHub Pages as:

- source: `Deploy from a branch`
- branch: `main`
- folder: `/docs`

The hero video `docs/okto-launch-loop.mp4` is intentionally committed because it is small enough for the launch site. Keep future generated videos small or move them to a CDN/Git LFS.
