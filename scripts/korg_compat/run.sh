#!/usr/bin/env bash
# Check fresh Okto exports with Korg's own verifiers at a pinned Korg commit:
# JS verifier, korg-ledger-py, and (if cargo is available) Rust JournalEvent
# deserialization. Usage: scripts/korg_compat/run.sh
set -euo pipefail

KORG_REF="b26e1f43548d9a7b1a5f5310efd426b2e5e63068"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KORG="$ROOT/.korg"

if [ ! -d "$KORG/.git" ]; then
  git clone --quiet https://github.com/New1Direction/korg "$KORG"
fi
git -C "$KORG" checkout --quiet "$KORG_REF"

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
uv run --project "$ROOT" python "$ROOT/scripts/korg_compat/make_sample.py" "$OUT"
KEY="$(cat "$OUT/chain.key")"
VERIFY_JS="$KORG/spec/korg-ledger-v1/js/bin.mjs"

echo "== Okto verifier"
uv run --project "$ROOT" okto korg verify "$OUT/plain.korg.jsonl"
uv run --project "$ROOT" okto korg verify "$OUT/keyed.korg.jsonl" --chain-key-file "$OUT/chain.key"

echo "== Korg JS verifier"
node "$VERIFY_JS" "$OUT/plain.korg.jsonl"
node "$VERIFY_JS" "$OUT/keyed.korg.jsonl" --key "$KEY"
if node "$VERIFY_JS" "$OUT/keyed.korg.jsonl" >/dev/null; then
  echo "keyed chain verified without its key" >&2
  exit 1
fi

echo "== korg-ledger-py"
python3 -I - "$KORG/adapters/korg-ledger-py/src" "$OUT" "$KEY" <<'PY'
import json, pathlib, sys
sys.path.insert(0, sys.argv[1])
from korg_ledger._hash import verify_chain, verify_dag
out, key = pathlib.Path(sys.argv[2]), sys.argv[3].encode()
for name, k in (("plain.korg.jsonl", None), ("keyed.korg.jsonl", key)):
    events = [json.loads(line) for line in (out / name).read_text().splitlines() if line]
    errors = verify_chain(events, k) + verify_dag(events)
    assert not errors, (name, errors)
    print(f"ok: {name}: {len(events)} events")
PY

if command -v cargo >/dev/null; then
  echo "== Korg Rust JournalEvent"
  RUSTFLAGS="-Awarnings" cargo run --quiet --manifest-path "$ROOT/scripts/korg_compat/rust/Cargo.toml" -- \
    "$OUT/plain.korg.jsonl" "$OUT/keyed.korg.jsonl"
else
  echo "cargo not found: skipping Rust JournalEvent check" >&2
fi
echo "Korg compatibility: PASS"
