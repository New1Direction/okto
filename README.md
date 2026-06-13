# selfHswarm

> Self-mutating swarm proxy for AI coding agents

**Three layers, one tool:**

1. **Self-patching proxy** — observes streaming anomalies and rewrites its own forwarding rules in real time
2. **Camouflage engine** — fabricates synthetic chaos sessions to stress-test agent behavior  
3. **RNA bus** — HLC-stamped distributed genome ledger that syncs protocol mutations across a fleet

## Install

```bash
uv tool install selfhswarm
# or
pip install selfhswarm
```

## Quick start

```bash
# Proxy Claude Code
selfhswarm run --client claude

# Proxy Gemini CLI
selfhswarm run --client gemini -- -p "hello"

# Run a chaos session
selfhswarm fabricate --scenario stream_mid_truncation --client claude

# Start the RNA broker (for multi-node swarms)
selfhswarm broker

# Connect to a broker
selfhswarm run --client claude --broker ws://localhost:9373

# Inspect local genome
selfhswarm genome list
```

## Supported clients

claude · gemini · codex · agy · kimi · kimi-code · cursor · opencode · pi · hermes
