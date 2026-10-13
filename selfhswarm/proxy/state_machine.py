"""
Layer 1 — Self-patching proxy.

The proxy state machine sits in front of the upstream LLM API.
It transitions through: NOMINAL → ANOMALY_DETECTED → PATCH_COMPUTING
→ PATCH_APPLIED → MONITORING → NOMINAL.

When a stream chunk is anomalous and no existing genome mutation applies,
the patch engine derives a minimal rewrite rule and emits it to the genome.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from selfhswarm.models import AgentClient, Mutation, MutationScope, ProxyState, StreamChunk

# ---------------------------------------------------------------------------
# Anomaly detectors
# ---------------------------------------------------------------------------

AnomalyDetector = Callable[[bytes], str | None]
"""Returns a human-readable anomaly description or None if clean."""


def _sse_prefix_check(chunk: bytes) -> str | None:
    """SSE chunks must start with 'data:', 'event:', 'id:', or be empty."""
    stripped = chunk.strip()
    if not stripped:
        return None
    if not any(stripped.startswith(p) for p in (b"data:", b"event:", b"id:", b":")):
        return f"SSE chunk missing known prefix: {stripped[:80]!r}"
    return None


def _json_parse_check(chunk: bytes) -> str | None:
    """data: {...} lines must contain valid JSON after the prefix."""
    import orjson

    stripped = chunk.strip()
    if not stripped.startswith(b"data:"):
        return None
    payload = stripped[5:].strip()
    if payload == b"[DONE]":
        return None
    try:
        orjson.loads(payload)
        return None
    except Exception:
        return f"JSON parse failure in SSE data line: {payload[:120]!r}"


def _empty_payload_check(chunk: bytes) -> str | None:
    """Catch completely empty non-whitespace responses."""
    if chunk and not chunk.strip():
        return "Response body is whitespace-only"
    return None


DEFAULT_DETECTORS: list[AnomalyDetector] = [
    _sse_prefix_check,
    _json_parse_check,
    _empty_payload_check,
]


def _anomaly_label(description: str) -> str:
    """Map a raw anomaly description to a compact display label."""
    d = description.lower()
    if "sse chunk missing" in d or "missing known prefix" in d:
        return "bare_json_without_data_prefix"
    if "json parse failure" in d:
        return "malformed_json_in_sse_frame"
    if "whitespace" in d or "whitespace-only" in d:
        return "empty_response_body"
    if "crlf" in d:
        return "line_ending_mismatch"
    return "protocol_anomaly"


# ---------------------------------------------------------------------------
# Patch engine
# ---------------------------------------------------------------------------


class PatchEngine:
    """
    Derives minimal rewrite rules from anomalous chunks.

    Strategy:
    1. Try each genome mutation for this client (newest HLC first).
    2. If a mutation's pattern matches the chunk, apply it and mark it reinforced.
    3. If no mutation matches, derive a new rule and return it.
    """

    def apply_genome(
        self,
        chunk: bytes,
        mutations: list[Mutation],
        scope: MutationScope,
    ) -> tuple[bytes, Mutation | None]:
        """
        Apply the first matching genome mutation to *chunk*.

        Returns (rewritten_chunk, applied_mutation_or_None).
        """
        for mut in sorted(mutations, key=lambda m: m.hlc, reverse=True):
            if mut.scope != scope:
                continue
            try:
                if not self._matches(chunk, mut):
                    continue
                rewritten = self._apply_one(chunk, mut)
                return rewritten, mut
            except Exception:
                continue
        return chunk, None

    def derive(
        self,
        raw: bytes,
        anomaly_description: str,
        client: AgentClient,
        scope: MutationScope,
        node_id: str,
        session_id: str,
        hlc_model,
    ) -> Mutation | None:
        """
        Attempt to derive a minimal repair mutation from an anomalous chunk.

        Returns a new Mutation or None if no derivation is possible.
        """
        repair = self._derive_repair(raw, anomaly_description)
        if repair is None:
            return None

        pattern_bytes, patch_bytes, patch_type = repair
        from selfhswarm.models import Mutation as Mut

        return Mut(
            hlc=hlc_model,
            client=client,
            scope=scope,
            pattern_hex=pattern_bytes.hex(),
            patch_hex=patch_bytes.hex(),
            patch_type=patch_type,
            description=anomaly_description,
            confidence=1.0,
            source_node=node_id,
            session_id=session_id,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _matches(self, chunk: bytes, mut: Mutation) -> bool:
        """True if *mut* would rewrite *chunk*; non-matching rules must not claim a repair."""
        if mut.patch_type == "literal":
            return bool(mut.pattern) and mut.pattern in chunk
        if mut.patch_type == "regex_sub":
            return re.search(mut.pattern, chunk) is not None
        # header_set is applied at the header layer; json_patch is not implemented.
        return False

    def _apply_one(self, chunk: bytes, mut: Mutation) -> bytes:
        if mut.patch_type == "literal":
            return chunk.replace(mut.pattern, mut.patch)
        if mut.patch_type == "regex_sub":
            return re.sub(mut.pattern, mut.patch, chunk)
        if mut.patch_type == "header_set":
            # header_set patches are applied at a higher level; skip here
            return chunk
        return chunk

    def _derive_repair(
        self, raw: bytes, description: str
    ) -> tuple[bytes, bytes, str] | None:
        """
        Minimal heuristic repair derivation.

        Returns (pattern, patch, patch_type) or None.
        """
        stripped = raw.strip()

        # Case: missing 'data:' prefix on what looks like JSON
        if stripped.startswith(b"{") or stripped.startswith(b"["):
            return (stripped, b"data: " + stripped, "literal")

        # Case: extra whitespace / CRLF confusion
        if b"\r\n" in raw and not raw.startswith(b"data:"):
            cleaned = raw.replace(b"\r\n", b"\n")
            return (raw, cleaned, "literal")

        # Case: [DONE] without 'data:' prefix
        if stripped == b"[DONE]":
            return (stripped, b"data: [DONE]", "literal")

        # No rule derivable
        return None


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


class ProxyStateMachine:
    """
    Per-session state machine for the self-patching proxy.

    Holds the current proxy state and drives transitions based on
    anomaly detection and patch availability.
    """

    def __init__(
        self,
        client: AgentClient,
        node_id: str,
        session_id: str,
        genome_mutations: list[Mutation],
        clock,  # HLCClock
        on_new_mutation: Callable[[Mutation], None] | None = None,
    ) -> None:
        self.client = client
        self.node_id = node_id
        self.session_id = session_id
        self._mutations = genome_mutations
        self._clock = clock
        self._on_new_mutation = on_new_mutation or (lambda _: None)
        self._state: ProxyState = ProxyState.NOMINAL
        self._patch_engine = PatchEngine()
        self._detectors = DEFAULT_DETECTORS
        self._anomaly_count = 0

    @property
    def state(self) -> ProxyState:
        return self._state

    def process_chunk(self, raw: bytes, scope: MutationScope) -> tuple[bytes, StreamChunk]:
        """
        Process one stream chunk through the state machine.

        Returns (possibly_rewritten_bytes, StreamChunk with metadata).
        """
        chunk_index = self._anomaly_count
        anomaly = self._detect(raw)
        applied_id: str | None = None
        anomaly_type_label: str | None = None
        expected_hex: str | None = None
        output = raw

        if anomaly:
            self._state = ProxyState.ANOMALY_DETECTED
            self._anomaly_count += 1
            anomaly_type_label = _anomaly_label(anomaly)

            # Try genome first
            output, applied = self._patch_engine.apply_genome(
                raw, self._mutations, scope
            )
            if applied:
                self._state = ProxyState.PATCH_APPLIED
                applied_id = applied.id
                expected_hex = output.hex()
                self._mutations = [
                    m.reinforced() if m.id == applied.id else m
                    for m in self._mutations
                ]
            else:
                # Derive new mutation
                self._state = ProxyState.PATCH_COMPUTING
                t = self._clock.tick()
                from selfhswarm.models import HLCModel

                hlc_model = HLCModel.from_hlc(t)
                new_mut = self._patch_engine.derive(
                    raw, anomaly, self.client, scope,
                    self.node_id, self.session_id, hlc_model
                )
                if new_mut:
                    self._mutations.append(new_mut)
                    self._on_new_mutation(new_mut)
                    output = self._patch_engine._apply_one(raw, new_mut)
                    applied_id = new_mut.id
                    expected_hex = output.hex()
                    self._state = ProxyState.PATCH_APPLIED
                else:
                    # Could not derive a fix; pass through raw and stay watchful
                    self._state = ProxyState.MONITORING
        else:
            if self._state in (ProxyState.PATCH_APPLIED, ProxyState.MONITORING):
                self._state = ProxyState.NOMINAL

        stream_chunk = StreamChunk(
            index=chunk_index,
            raw_hex=raw.hex(),
            anomalous=bool(anomaly),
            applied_mutation_id=applied_id,
            anomaly_type=anomaly_type_label,
            expected_hex=expected_hex,
        )
        return output, stream_chunk

    def _detect(self, chunk: bytes) -> str | None:
        for detector in self._detectors:
            result = detector(chunk)
            if result:
                return result
        return None
