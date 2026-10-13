# Exporting to Korg

[Korg](https://github.com/New1Direction/korg) keeps tamper-evident, hash-chained ledgers of agent sessions. `okto korg export` turns one Okto capture into a Korg ledger file so the protocol failures Okto saw and repaired sit next to the agent's own events.

The export is one-way and sanitized. HTTPS interception, raw captures, and the mutation genome stay in Okto. What crosses is labels, counts, keyed fingerprints, replay evidence, provenance, and causal links.

## Quick start

```bash
okto korg export <session-id> -o session.korg.jsonl   # from ~/.okto/sessions
okto korg export ./capture.jsonl -o out.jsonl          # any capture file, incl. `okto fabricate` output
okto korg verify session.korg.jsonl                    # chain, DAG, schema allowlist, secret scan
okto korg export --all --output-dir exports/           # every capture, one file each

# Korg's own verifiers accept the file unchanged
korg-verify session.korg.jsonl
npx @korgg/ledger-verify session.korg.jsonl

# Tamper-proof mode: HMAC-keyed chain (Korg spec §3), verifiable only with the key
okto korg export <session-id> --chain-key-file ~/.okto/korg_chain.key -o keyed.jsonl
okto korg verify keyed.jsonl --chain-key-file ~/.okto/korg_chain.key
korg-verify keyed.jsonl --key "$(cat ~/.okto/korg_chain.key)"
```

| Option | Default | Meaning |
|---|---|---|
| `--session-dir` | `~/.okto/sessions` | Where a session id is looked up |
| `--all` | off | Export every capture in `--session-dir` |
| `--output`, `-o` | stdout | Output file, written atomically with mode `0600` |
| `--output-dir` | — | Required for several captures; files are named `<session-ref>.korg.jsonl` (a fingerprint, not the session id) |
| `--genome` | `~/.okto/genome.jsonl` | Genome for repair summaries and replay |
| `--no-replay` | off | Skip replay evidence |
| `--key-file` | `~/.okto/korg_export.key` | Local HMAC key for fingerprints, created on first use (mode `0600`) |
| `--chain-key-file` | none | HMAC-key the hash chain. Created on first use (mode `0600`) as text, because Korg's verifiers take `--key <string>` |

If a boundary check fails for a capture, nothing is written for it and the error names the failing event and field, never the value that tripped the check. In a batch, the other captures are still exported and the command exits non-zero.

## Contract

| | |
|---|---|
| Korg format | `korg-ledger@v1` (frozen): JSONL `JournalEvent`, SHA-256 hash chain, `prev_hash` from the genesis value `"0" * 64` |
| Korg event | `AgentToolCall` (agent_event_spec §1.2), `source_agent = agent:okto@<version>`, `metadata.actor_id = okto:korg-export` |
| Okto schema | `okto-korg-export@1`, stamped in every event's `metadata.tags["okto.export_schema"]` and in the manifest |
| Redaction policy | `okto-redaction@1` |
| Fingerprints | `hmac-sha256:<64 hex>` under the local key |

Compatibility is checked two ways:

- Unit tests reproduce Korg's frozen conformance vectors (`tests/fixtures/korg-ledger-v1`).
- `scripts/korg_compat/run.sh`, run in CI as the "Korg compatibility" job, exports sample captures, plain and keyed. It checks them with Korg's JS verifier and `korg-ledger-py`, and deserializes them as Korg's Rust `korg_registry::log::JournalEvent`. Korg is pinned to a commit in the script and the workflow; bump both together.

A breaking change to the event shapes below bumps the Okto schema to `okto-korg-export@2`. Additive fields keep `@1`, and `okto korg verify` rejects any field it does not know.

### Events and causality

`metadata.triggered_by` holds the parent `seq_id`. `metadata.causation_id` holds the parent's `event_id`. Event IDs are UUIDv5 values derived from the session fingerprint, so re-exporting with the same key gives identical bytes.

```diagram
┌──────────────────────────────────────────────┐
│ 1 user_prompt  (synthesized root, provenance)│
└──────────────────────────────────────────────┘
  ├─ llm_inference  turn 0          spine (Korg spec §2a)
  │   ├─ okto.anomaly  chunk k      one per anomalous chunk
  │   │   └─ okto.repair            first application of each mutation
  │   └─ llm_inference  turn 1 …
  ├─ okto.replay                    replay against the current genome
  │   └─ okto.replay_check          one per anomalous chunk
  └─ okto.export_manifest           always last
```

| `tool_name` | `args` | `result` |
|---|---|---|
| `user_prompt` | `synthesized: true`, `origin: "okto.session"`, `prompt_exported: false` | `session_ref`, `client`, `provider_vendor`, `provider_product`, `provider_host`¹, `tls_established`, `synthetic`, `scenario`¹, `turn_count`, `capture_node`¹, `okto_version` |
| `llm_inference` | `turn_index`, `model`¹, `stream`¹ | `status_code`, `chunk_count`, `anomalies_detected`, `repairs_applied`, token counts¹ |
| `okto.anomaly` | `turn_index`, `chunk_position`, `anomaly_type` | `repaired`, `output_changed`, `mutation_id`¹, `raw_fingerprint`, `raw_size_bytes`, `repaired_fingerprint`¹ |
| `okto.repair` | `mutation_id`, `anomaly_type`, `scope`¹, `patch_type`¹ | `in_genome`, `applications`, `confidence_bp`¹, `reinforcement_count`¹, `origin_node`¹, `pattern_fingerprint`¹, `patch_fingerprint`¹, `pattern_size_bytes`¹, `patch_size_bytes`¹ |
| `okto.replay` | `engine`, `genome_fingerprint`, `genome_mutations` | `turns`, `anomalies`, `repaired`, `resolved`, `regressions`, `newly_repaired`, `matches_capture`, `unresolved_anomaly_types` |
| `okto.replay_check` | `turn_index`, `chunk_position`, `anomaly_type` | `captured_repaired`, `replay_repaired`, `replay_output_changed`, `matches_capture`, `replay_output_fingerprint`¹, `mutation_id`¹ |
| `okto.export_manifest` | `export_schema`, `korg_spec`, `redaction_policy`, `fingerprint_scheme`, `fingerprint_key_id`, `source_fingerprint`, `chain_hash` (`sha256` or `hmac-sha256`) | `events`, `anomalies`, `repairs`, `replay_checks`, `withheld` |

¹ Optional: present only when known and safe to export.

Notes:

- `anomaly_type` is one of `bare_json_without_data_prefix`, `malformed_json_in_sse_frame`, `empty_response_body`, `line_ending_mismatch`, `protocol_anomaly`.
- `confidence_bp` is confidence in basis points (0–10000). Korg ledgers carry integers only.
- `output_changed: false` with `repaired: true` means a matching mutation was applied but left the bytes unchanged.
- `okto.replay` `success` is false when the replay leaves anomalies unresolved or a capture-time repair no longer happens (`regressions > 0`).
- `matches_capture` compares the fingerprint of the replay output with the fingerprint of the output recorded at capture time.

## What never crosses

The manifest's `withheld` list names these categories:

- request and response headers (including `authorization`, `x-api-key`, cookies)
- request bodies: prompts, system prompts, messages, tool payloads
- raw and repaired stream chunk bytes
- mutation byte patterns and patches, and anomaly descriptions (they embed raw bytes)
- request targets and query strings
- session ids and node ids, which are exported only as fingerprints
- provider hosts that Okto does not recognize, which may be internal gateways
- the fingerprint key and the chain key

## How the boundary is enforced

`selfhswarm/korg/boundary.py` runs three independent layers on every line before anything is written:

1. **Structural allowlist.** The envelope must match Korg's `JournalEvent` and `AgentToolCall` shape exactly. Every `args`/`result` key must appear in the table above, with a value of the declared kind: int, bool, enum, UUID, fingerprint, model name, or hostname. There is no free-text field. Floats and fields larger than 1 KiB are rejected; Korg's content-ref threshold is 1 KiB, and Okto never exports blobs.
2. **Secret scan.** Each line is checked for provider API keys, bearer and basic auth tokens, JWTs, AWS and GitHub tokens, Slack tokens, private keys, `key=value` credentials, URL userinfo, and long hex or base64 runs.
3. **Canary scan.** Strings harvested from the source capture must not appear in plain or hex form. These include sensitive header values, every request body string except `model`, stream chunk text and JSON leaves, mutation patterns, and the fingerprint key.

Fingerprints are keyed, so a Korg reader can match equal values across exports from the same Okto install but cannot confirm a guess about the underlying bytes. Keep `korg_export.key` private. Rotating it breaks correlation with earlier exports. `fingerprint_key_id` shows which key produced a file.

## Trust notes

- A Korg ledger is tamper-evident, not confidential. Treat an export as shareable diagnostics, and do not use it to carry secrets.
- Korg v1 trusts `source_agent` as given (Korg spec §7.7). An Okto export proves the file has not changed since it was written. It does not prove which machine wrote it.
- `okto korg verify` checks structure and secrets without the source capture. The canary layer needs the capture and runs only at export time.
