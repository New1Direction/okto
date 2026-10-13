"""
The Okto → Korg trust boundary.

Okto keeps raw captures (headers, bodies, stream bytes, mutation byte
patterns) local. Only values that pass this module may cross into a Korg
ledger. The boundary has three independent layers; an export must pass all
three or nothing is written:

1. **Structural allowlist.** Every exported event must match a fixed
   envelope, and every ``args``/``result`` key must be declared in
   ``TOOL_SCHEMAS`` with a value of the declared kind (int, bool, enum,
   fingerprint, UUID, model name, …). There is no free-text field, so raw
   content has nowhere to go.
2. **Secret scan.** Each serialized line is checked for credential shapes
   (provider API keys, bearer tokens, JWTs, cloud keys, private keys,
   ``key=value`` secrets) and for long hex/base64 runs that would indicate
   leaked raw bytes.
3. **Canary scan.** Strings harvested from the source capture (sensitive
   header values, request/response payload strings, mutation patterns) must
   not appear in the output, in plain or hex form.

Fingerprints are HMAC-SHA256 under a key that never leaves the machine, so a
Korg reader can correlate equal values across exports from the same Okto
install but cannot confirm guesses about the underlying bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import pathlib
import re
import secrets
from collections.abc import Iterable
from typing import Any

import orjson

from selfhswarm.models import AgentClient, Mutation, MutationScope, Session
from selfhswarm.proxy.state_machine import _anomaly_label

from .ledger import canonicalize

EXPORT_SCHEMA = "okto-korg-export@1"
REDACTION_POLICY = "okto-redaction@1"
FINGERPRINT_SCHEME = "hmac-sha256"
ACTOR_ID = "okto:korg-export"

#: Korg agent_event_spec §7.3: field values above this size must be content-
#: referenced. Okto never exports content, so it rejects them instead.
MAX_FIELD_BYTES = 1024

#: Categories that are never exported. Listed in the manifest so a Korg
#: reader knows what exists locally but was withheld.
WITHHELD = (
    "request_headers",
    "response_headers",
    "request_body",
    "stream_chunk_bytes",
    "repaired_chunk_bytes",
    "mutation_patterns",
    "anomaly_descriptions",
    "request_target",
)

ANOMALY_TYPES = frozenset(
    {
        "bare_json_without_data_prefix",
        "malformed_json_in_sse_frame",
        "empty_response_body",
        "line_ending_mismatch",
        "protocol_anomaly",
    }
)

TOKEN_USAGE_KEYS = frozenset(
    {
        "input_tokens",
        "output_tokens",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
    }
)

KNOWN_VENDORS = frozenset(
    {"Anthropic", "OpenAI", "Google", "Moonshot AI", "Cursor", "OpenCode", "NousResearch",
     "Unknown"}
)
KNOWN_PRODUCTS = frozenset(
    {"Claude", "GPT", "ChatGPT", "Gemini", "Antigravity", "Kimi", "Cursor", "OpenCode",
     "Hermes", "Unknown"}
)

_FP_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,99}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+[A-Za-z0-9.+-]{0,32}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_SAFE_INT_MAX = 2**53 - 1


class BoundaryViolationError(ValueError):
    """Raised when an export would carry data that must stay inside Okto."""


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------


class Fingerprinter:
    """Keyed digests for values that may be referenced but not revealed."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("fingerprint key must be at least 32 bytes")
        self._key = key

    @classmethod
    def load_or_create(cls, path: pathlib.Path) -> Fingerprinter:
        """Read the local key, creating a random 32-byte key (mode 0600) if missing."""
        path = pathlib.Path(path)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
        return cls(path.read_bytes())

    def __call__(self, data: bytes | str) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        digest = hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return f"{FINGERPRINT_SCHEME}:{digest}"

    @property
    def key_id(self) -> str:
        """Stable, non-reversible identifier for the key (lets readers group exports)."""
        return hashlib.sha256(b"okto-korg-key-id\x00" + self._key).hexdigest()[:16]

    def canaries(self) -> set[str]:
        return {self._key.hex()}


# ---------------------------------------------------------------------------
# Sanitizers: map local values onto exportable ones (or drop them)
# ---------------------------------------------------------------------------


def anomaly_type(label: str | None) -> str:
    return label if label in ANOMALY_TYPES else "protocol_anomaly"


def mutation_anomaly_type(mutation: Mutation) -> str:
    """Label for a mutation. ``description`` carries raw bytes, so only its label leaves."""
    return anomaly_type(_anomaly_label(mutation.description))


def model_name(value: Any) -> str | None:
    if isinstance(value, str) and _MODEL_RE.match(value) and not _secret_hits(value):
        return value
    return None


def provider_host(hostname: str | None, vendor: str) -> str | None:
    """Only hosts of known providers are exported; unknown hosts may be internal."""
    if vendor == "Unknown" or not hostname:
        return None
    host = hostname.lower().rsplit(":", 1)[0]
    return host if _HOST_RE.match(host) else None


def uuid_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and _UUID_RE.match(value) else None


def token_usage(usage: dict[str, Any]) -> dict[str, int]:
    return {
        k: v
        for k, v in usage.items()
        if k in TOKEN_USAGE_KEYS and isinstance(v, int) and not isinstance(v, bool)
        and 0 <= v <= _SAFE_INT_MAX
    }


# ---------------------------------------------------------------------------
# Layer 1: structural allowlist
# ---------------------------------------------------------------------------

# kind names → validator
def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _SAFE_INT_MAX


_KINDS: dict[str, Any] = {
    "int": _is_int,
    "bool": lambda v: isinstance(v, bool),
    "true": lambda v: v is True,
    "false": lambda v: v is False,
    "fp": lambda v: isinstance(v, str) and bool(_FP_RE.match(v)),
    "key_id": lambda v: isinstance(v, str) and bool(_KEY_ID_RE.match(v)),
    "uuid": lambda v: isinstance(v, str) and bool(_UUID_RE.match(v)),
    "model": lambda v: isinstance(v, str) and bool(_MODEL_RE.match(v)),
    "host": lambda v: isinstance(v, str) and bool(_HOST_RE.match(v)),
    "version": lambda v: isinstance(v, str) and bool(_VERSION_RE.match(v)),
    "anomaly": lambda v: v in ANOMALY_TYPES,
    "anomaly_list": lambda v: isinstance(v, list) and len(v) == len(set(v))
    and all(x in ANOMALY_TYPES for x in v),
    "withheld": lambda v: isinstance(v, list) and all(x in WITHHELD for x in v),
    "client": lambda v: v in {c.value for c in AgentClient},
    "scope": lambda v: v in {s.value for s in MutationScope},
    "patch_type": lambda v: v in {"literal", "regex_sub", "json_patch", "header_set"},
    "vendor": lambda v: v in KNOWN_VENDORS,
    "product": lambda v: v in KNOWN_PRODUCTS,
    "scenario": lambda v: isinstance(v, str) and bool(re.fullmatch(r"[a-z_]{1,40}", v)),
}


def _const(value: str):
    return lambda v: v == value


def _fields(required: dict[str, str], optional: dict[str, str] | None = None):
    return {"required": required, "optional": optional or {}}


_TOKENS = {k: "int" for k in sorted(TOKEN_USAGE_KEYS)}

#: tool_name → (args schema, result schema). The only shapes that may cross.
TOOL_SCHEMAS: dict[str, tuple[dict, dict]] = {
    "user_prompt": (
        _fields({"synthesized": "true", "origin": "const:okto.session",
                 "prompt_exported": "false"}),
        _fields(
            {"session_ref": "fp", "client": "client", "provider_vendor": "vendor",
             "provider_product": "product", "tls_established": "bool", "synthetic": "bool",
             "turn_count": "int", "okto_version": "version"},
            {"provider_host": "host", "capture_node": "fp", "scenario": "scenario"},
        ),
    ),
    "llm_inference": (
        _fields({"turn_index": "int"}, {"model": "model", "stream": "bool"}),
        _fields(
            {"status_code": "int", "chunk_count": "int", "anomalies_detected": "int",
             "repairs_applied": "int"},
            _TOKENS,
        ),
    ),
    "okto.anomaly": (
        _fields({"turn_index": "int", "chunk_position": "int", "anomaly_type": "anomaly"}),
        _fields(
            {"repaired": "bool", "output_changed": "bool", "raw_fingerprint": "fp",
             "raw_size_bytes": "int"},
            {"mutation_id": "uuid", "repaired_fingerprint": "fp"},
        ),
    ),
    "okto.repair": (
        _fields({"mutation_id": "uuid", "anomaly_type": "anomaly"},
                {"scope": "scope", "patch_type": "patch_type"}),
        _fields(
            {"in_genome": "bool", "applications": "int"},
            {"confidence_bp": "int", "reinforcement_count": "int", "origin_node": "fp",
             "pattern_fingerprint": "fp", "patch_fingerprint": "fp",
             "pattern_size_bytes": "int", "patch_size_bytes": "int"},
        ),
    ),
    "okto.replay": (
        _fields({"engine": "const:okto-state-machine", "genome_fingerprint": "fp",
                 "genome_mutations": "int"}),
        _fields({"turns": "int", "anomalies": "int", "repaired": "int", "resolved": "bool",
                 "regressions": "int", "newly_repaired": "int", "matches_capture": "bool",
                 "unresolved_anomaly_types": "anomaly_list"}),
    ),
    "okto.replay_check": (
        _fields({"turn_index": "int", "chunk_position": "int", "anomaly_type": "anomaly"}),
        _fields(
            {"captured_repaired": "bool", "replay_repaired": "bool",
             "replay_output_changed": "bool", "matches_capture": "bool"},
            {"replay_output_fingerprint": "fp", "mutation_id": "uuid"},
        ),
    ),
    "okto.export_manifest": (
        _fields({"export_schema": f"const:{EXPORT_SCHEMA}", "korg_spec": "const:korg-ledger@v1",
                 "redaction_policy": f"const:{REDACTION_POLICY}",
                 "fingerprint_scheme": f"const:{FINGERPRINT_SCHEME}",
                 "fingerprint_key_id": "key_id", "source_fingerprint": "fp"}),
        _fields({"events": "int", "anomalies": "int", "repairs": "int", "replay_checks": "int",
                 "withheld": "withheld"}),
    ),
}

TOOL_KIND = {
    "user_prompt": "session",
    "llm_inference": "turn",
    "okto.anomaly": "anomaly",
    "okto.repair": "repair",
    "okto.replay": "replay",
    "okto.replay_check": "replay_check",
    "okto.export_manifest": "manifest",
}

_TOP_KEYS = {"schema_version", "seq_id", "metadata", "event", "prev_hash", "entry_hash"}
_META_KEYS = {
    "event_id", "correlation_id", "causation_id", "root_event_id", "actor_id", "campaign_id",
    "emitted_at", "branch_id", "speculative", "retry_count", "tier", "span_id", "tags",
    "triggered_by",
}
_EVENT_KEYS = {
    "event_type", "source_agent", "tool_name", "args", "result", "payload_refs", "success",
    "duration_ms", "timestamp",
}
_TAG_KEYS = {"okto.export_schema", "okto.kind", "okto.session_ref"}
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_AGENT_RE = re.compile(r"^agent:okto@\d+\.\d+\.\d+[A-Za-z0-9.+-]{0,32}$")


def _check_value(kind: str, value: Any) -> bool:
    if kind.startswith("const:"):
        return _const(kind[6:])(value)
    return bool(_KINDS[kind](value))


def _check_fields(where: str, schema: dict, payload: Any, errors: list[str]) -> None:
    if not isinstance(payload, dict):
        errors.append(f"{where}: not an object")
        return
    allowed = {**schema["required"], **schema["optional"]}
    for key in payload:
        if key not in allowed:
            errors.append(f"{where}.{key}: field not in export allowlist")
    for key in schema["required"]:
        if key not in payload:
            errors.append(f"{where}.{key}: required field missing")
    for key, kind in allowed.items():
        if key in payload:
            value = payload[key]
            if not _check_value(kind, value):
                errors.append(f"{where}.{key}: value is not a valid {kind}")
            elif len(canonicalize(value)) > MAX_FIELD_BYTES:
                errors.append(f"{where}.{key}: value exceeds {MAX_FIELD_BYTES} bytes")


def check_structure(record: Any) -> list[str]:
    """Layer 1. Empty list iff *record* is a well-formed Okto export event."""
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["record is not an object"]
    seq = record.get("seq_id")
    where = f"seq {seq}"
    if set(record) != _TOP_KEYS:
        errors.append(f"{where}: top-level keys {sorted(set(record) ^ _TOP_KEYS)} unexpected")
    if record.get("schema_version") != "1.0":
        errors.append(f"{where}: schema_version must be '1.0'")
    if not _is_int(seq) or seq < 1:
        errors.append(f"{where}: seq_id must be a positive integer")
    for field in ("prev_hash", "entry_hash"):
        if not (isinstance(record.get(field), str) and _HASH_RE.match(record[field])):
            errors.append(f"{where}: {field} must be 64 lowercase hex chars")

    meta = record.get("metadata")
    if not isinstance(meta, dict) or set(meta) != _META_KEYS:
        errors.append(f"{where}: metadata keys do not match the Korg JournalEvent shape")
        meta = meta if isinstance(meta, dict) else {}
    for f in ("event_id", "correlation_id", "root_event_id", "campaign_id"):
        if f in meta and not _KINDS["uuid"](meta[f]):
            errors.append(f"{where}: metadata.{f} must be a UUID")
    for f in ("causation_id", "branch_id", "span_id"):
        if meta.get(f) is not None and not _KINDS["uuid"](meta[f]):
            errors.append(f"{where}: metadata.{f} must be a UUID or null")
    if meta.get("actor_id", ACTOR_ID) != ACTOR_ID:
        errors.append(f"{where}: metadata.actor_id must be {ACTOR_ID!r}")
    if meta.get("tier", "Telemetry") != "Telemetry":
        errors.append(f"{where}: metadata.tier must be 'Telemetry'")
    if meta.get("speculative", False) is not False or meta.get("retry_count", 0) != 0:
        errors.append(f"{where}: metadata.speculative/retry_count must be false/0")
    tb = meta.get("triggered_by")
    if tb is not None and not _is_int(tb):
        errors.append(f"{where}: metadata.triggered_by must be an integer or null")
    hlc = meta.get("emitted_at", {})
    if not (isinstance(hlc, dict) and set(hlc) == {"physical", "logical", "actor_id"}
            and all(_is_int(v) for v in hlc.values())):
        errors.append(f"{where}: metadata.emitted_at must be an HLC timestamp")
    tags = meta.get("tags", {})
    if not isinstance(tags, dict) or set(tags) != _TAG_KEYS:
        errors.append(f"{where}: metadata.tags must contain exactly {sorted(_TAG_KEYS)}")
        tags = {}
    if tags and tags.get("okto.export_schema") != EXPORT_SCHEMA:
        errors.append(f"{where}: unsupported export schema {tags.get('okto.export_schema')!r}")
    if tags and not _KINDS["fp"](tags.get("okto.session_ref")):
        errors.append(f"{where}: tags.okto.session_ref must be a fingerprint")

    event = record.get("event")
    if not isinstance(event, dict) or set(event) != _EVENT_KEYS:
        errors.append(f"{where}: event keys do not match the AgentToolCall shape")
        return errors
    if event.get("event_type") != "AgentToolCall":
        errors.append(f"{where}: event_type must be 'AgentToolCall'")
    if not (isinstance(event.get("source_agent"), str)
            and _SOURCE_AGENT_RE.match(event["source_agent"])):
        errors.append(f"{where}: source_agent must be agent:okto@<version>")
    if event.get("payload_refs") != []:
        errors.append(f"{where}: payload_refs must be empty (Okto never exports blobs)")
    if not isinstance(event.get("success"), bool):
        errors.append(f"{where}: success must be a boolean")
    if not _is_int(event.get("duration_ms")):
        errors.append(f"{where}: duration_ms must be a non-negative integer")
    if not (isinstance(event.get("timestamp"), str) and _TIMESTAMP_RE.match(event["timestamp"])):
        errors.append(f"{where}: timestamp must be ISO-8601 UTC with milliseconds")
    tool = event.get("tool_name")
    if tool not in TOOL_SCHEMAS:
        errors.append(f"{where}: tool_name {tool!r} is not an Okto export event")
        return errors
    if tags and tags.get("okto.kind") != TOOL_KIND[tool]:
        errors.append(f"{where}: tags.okto.kind does not match tool_name")
    args_schema, result_schema = TOOL_SCHEMAS[tool]
    _check_fields(f"{where} {tool}.args", args_schema, event.get("args"), errors)
    _check_fields(f"{where} {tool}.result", result_schema, event.get("result"), errors)
    return errors


# ---------------------------------------------------------------------------
# Layer 2: secret scan
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("provider_api_key", re.compile(r"sk-[A-Za-z0-9_-]{16,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{30,}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("basic_auth", re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("credential_assignment", re.compile(
        r"(?i)\b(?:authorization|proxy-authorization|x-api-key|x-goog-api-key|api[_-]?key"
        r"|cookie|set-cookie|password|passwd|secret|access[_-]?token|refresh[_-]?token)"
        r"\b(?:\\?[\"'])?\s*[:=]"
    )),
    ("url_userinfo", re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@\"]+:[^/\s@\"]+@")),
    ("raw_hex_run", re.compile(r"[0-9a-fA-F]{65,}")),
    ("raw_base64_run", re.compile(r"[A-Za-z0-9+/_-]{80,}={0,2}")),
)


def _secret_hits(text: str) -> list[str]:
    return [name for name, pattern in _SECRET_PATTERNS if pattern.search(text)]


# ---------------------------------------------------------------------------
# Layer 3: canaries harvested from the source capture
# ---------------------------------------------------------------------------

_CANARY_MIN_LEN = 8
# Header values that carry no secrets and that the export may legitimately echo.
_BENIGN_HEADERS = frozenset(
    {"host", "content-type", "content-length", "connection", "transfer-encoding", "accept",
     "accept-encoding", "content-encoding", "date", "server", "vary", "cache-control",
     "keep-alive", "anthropic-version"}
)
_NON_SECRET_RE = re.compile(r"^[\d\s:.,+\-TZ/]+$")  # dates, numbers, versions
# Short hex strings (commit prefixes, request ids) can collide by chance with
# the export's own 64-hex digests; they are too short to be credentials.
_SHORT_HEX_RE = re.compile(r"^[0-9a-fA-F]{1,23}$")


def _string_leaves(value: Any, skip_keys: frozenset[str] = frozenset()) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and len(k) >= _CANARY_MIN_LEN:
                yield k
            if k not in skip_keys:
                yield from _string_leaves(v)
    elif isinstance(value, list):
        for v in value:
            yield from _string_leaves(v)


def _bytes_canaries(data: bytes) -> Iterable[str]:
    text = data.decode("utf-8", errors="replace")
    yield text.strip()
    for line in text.splitlines():
        line = line.strip()
        yield line
        payload = line[5:].strip() if line.startswith("data:") else line
        yield payload
        try:
            yield from _string_leaves(orjson.loads(payload))
        except orjson.JSONDecodeError:
            pass


def collect_canaries(session: Session, mutations: Iterable[Mutation] = ()) -> set[str]:
    """Strings from the local capture that must never appear in an export."""
    found: set[str] = set()
    for turn in session.turns:
        for headers in (turn.request_headers, turn.response_headers):
            for name, value in headers.items():
                if name.lower() in _BENIGN_HEADERS:
                    continue
                found.add(value)
                found.update(value.split())  # "Bearer <token>" → "<token>"
        if turn.request_body is not None:
            # `model` is exported deliberately (sanitized); every other string stays local.
            found.update(_string_leaves(turn.request_body, skip_keys=frozenset({"model"})))
        for chunk in turn.stream_chunks:
            for hex_value in (chunk.raw_hex, chunk.expected_hex):
                if hex_value:
                    found.update(_bytes_canaries(bytes.fromhex(hex_value)))
    for mut in mutations:
        found.update(_bytes_canaries(mut.pattern))
        found.update(_bytes_canaries(mut.patch))
        found.add(mut.description)
    return {
        c for c in found
        if isinstance(c, str) and len(c) >= _CANARY_MIN_LEN
        and not _NON_SECRET_RE.match(c) and not _SHORT_HEX_RE.match(c)
    }


# ---------------------------------------------------------------------------
# Guard: all three layers
# ---------------------------------------------------------------------------


class _CanaryIndex:
    """
    Substring search for many canaries at once: canaries are bucketed by
    their first ``_CANARY_MIN_LEN`` chars, so a line is scanned once instead
    of once per canary.
    """

    def __init__(self, canaries: Iterable[str], published: Iterable[str]) -> None:
        self.published = sorted({p for p in published if p}, key=len, reverse=True)
        skip = set(self.published)
        self.plain: dict[str, list[str]] = {}
        self.hexed: dict[str, list[str]] = {}
        for c in set(canaries):
            if not c or c in skip or len(c) < _CANARY_MIN_LEN:
                continue
            h = c.encode("utf-8").hex()
            self.plain.setdefault(c[:_CANARY_MIN_LEN], []).append(c)
            self.hexed.setdefault(h[:_CANARY_MIN_LEN], []).append(h)

    def leaks(self, line: str) -> bool:
        if not self.plain:
            return False
        # Values published on purpose (sanitized model names, provider hosts)
        # are masked so a canary that is a substring of them is not a hit.
        masked = line
        for value in self.published:
            masked = masked.replace(value, "\x00")
        n = _CANARY_MIN_LEN
        for text, index in ((masked, self.plain), (masked.lower(), self.hexed)):
            for i in range(len(text) - n + 1):
                for c in index.get(text[i : i + n], ()):
                    if text.startswith(c, i):
                        return True
        return False


def _check_line(line: str, index: _CanaryIndex) -> list[str]:
    errors = [f"secret pattern {name!r} present" for name in _secret_hits(line)]
    if index.leaks(line):
        # Never echo the canary itself: the error message may be logged.
        errors.append("source capture value leaked")
    return errors


def check_line(
    line: str,
    canaries: Iterable[str] = (),
    published: Iterable[str] = (),
) -> list[str]:
    """Layers 2 and 3 for one serialized record (canaries shorter than 8 chars are ignored)."""
    return _check_line(line, _CanaryIndex(canaries, published))


def guard(
    records: list[dict],
    canaries: Iterable[str] = (),
    published: Iterable[str] = (),
) -> list[bytes]:
    """
    Serialize *records* to JSONL lines, enforcing every boundary layer.
    Raises BoundaryViolationError (naming the seq/field, never the leaked value).
    """
    index = _CanaryIndex(canaries, published)
    lines: list[bytes] = []
    errors: list[str] = []
    for record in records:
        errors.extend(check_structure(record))
        line = orjson.dumps(record).decode("utf-8")
        errors.extend(f"seq {record.get('seq_id')}: {e}" for e in _check_line(line, index))
        lines.append(line.encode("utf-8") + b"\n")
    if errors:
        raise BoundaryViolationError("; ".join(errors[:20]))
    return lines
