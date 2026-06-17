# Contributing

Thanks for improving Okto.

## Development setup

```bash
uv sync --all-extras --dev
uv run pytest -q
uv run ruff check .
uv run okto --help
uv build
```

## Ground rules

- Keep Python 3.11 and 3.12 working.
- Add or update tests for proxy parsing, mutation rules, ledger behavior, and viewer APIs.
- Do not commit captured agent sessions, local TLS keys, API tokens, binaries, generated videos, or reverse-engineering scratch files.
- Treat MITM/proxy changes as security-sensitive: narrow parsing, explicit timeouts, no surprise network calls.
- Keep public copy concrete. No vague AI hype. Say what Okto observes, changes, stores, and risks.

## Pull request checklist

- [ ] Tests pass locally.
- [ ] Ruff passes locally.
- [ ] `uv run okto --help` works.
- [ ] New behavior is documented in `README.md` or inline docstrings.
- [ ] No secrets, private session data, or large generated assets are included.
