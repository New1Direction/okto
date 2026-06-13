"""
Core data models for selfhswarm.

All models are Pydantic v2 with orjson-backed serialisation for
high-throughput streaming scenarios.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from selfhswarm.hlc import HLC


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class MutationScope(str, Enum):
    """Where in the HTTP exchange a mutation applies."""

    REQUEST_HEADER = "request_header"
    REQUEST_BODY = "request_body"
    RESPONSE_HEADER = "response_header"
    RESPONSE_BODY = "response_body"
    STREAM_CHUNK = "stream_chunk"


class ProxyState(str, Enum):
    """States of the self-patching proxy state machine."""

    NOMINAL = "nominal"
    ANOMALY_DETECTED = "anomaly_detected"
    PATCH_COMPUTING = "patch_computing"
    PATCH_APPLIED = "patch_applied"
    MONITORING = "monitoring"


class AgentClient(str, Enum):
    """Supported agent CLI clients."""

    CLAUDE = "claude"
    GEMINI = "gemini"
    CODEX = "codex"
    AGY = "agy"           # Antigravity CLI
    KIMI = "kimi"
    KIMI_CODE = "kimi-code"
    CURSOR = "cursor"
    OPENCODE = "opencode"
    PI = "pi"
    HERMES = "hermes"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# HLC adapter for Pydantic
# ---------------------------------------------------------------------------


class HLCModel(BaseModel):
    """Pydantic-serialisable wrapper around HLC."""

    wall_ms: int
    counter: int
    node_id: str

    def to_hlc(self) -> HLC:
        return HLC(wall_ms=self.wall_ms, counter=self.counter, node_id=self.node_id)

    @classmethod
    def from_hlc(cls, h: HLC) -> "HLCModel":
        return cls(wall_ms=h.wall_ms, counter=h.counter, node_id=h.node_id)

    def __lt__(self, other: "HLCModel") -> bool:
        return self.to_hlc() < other.to_hlc()

    def __le__(self, other: "HLCModel") -> bool:
        return self.to_hlc() <= other.to_hlc()


# ---------------------------------------------------------------------------
# Mutation — atomic unit of the genome
# ---------------------------------------------------------------------------


class Mutation(BaseModel):
    """
    A single learned protocol rewrite rule.

    The genome is an ordered list of Mutations, stamped by HLC.
    Each Mutation encodes: what pattern triggered it, how to rewrite it,
    and how confident we are in the rule.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hlc: HLCModel
    client: AgentClient = AgentClient.UNKNOWN
    scope: MutationScope
    # Stored as hex strings (bytes aren't JSON-safe)
    pattern_hex: str  # regex or literal bytes (hex-encoded) that triggered
    patch_hex: str  # replacement bytes (hex-encoded)
    patch_type: Literal["literal", "regex_sub", "json_patch", "header_set"] = "literal"
    description: str = ""  # human-readable note from the patch engine
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_node: str = ""
    session_id: str = ""
    reinforcement_count: int = 0

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, v))

    @property
    def pattern(self) -> bytes:
        return bytes.fromhex(self.pattern_hex)

    @property
    def patch(self) -> bytes:
        return bytes.fromhex(self.patch_hex)

    def decayed(self, hours_elapsed: float, decay_rate: float = 0.05 / 24) -> "Mutation":
        """Return a copy with confidence decayed proportionally to elapsed time."""
        new_conf = max(0.0, self.confidence - decay_rate * hours_elapsed)
        return self.model_copy(update={"confidence": new_conf})

    def reinforced(self) -> "Mutation":
        """Return a copy with confidence reset and reinforcement count incremented."""
        return self.model_copy(
            update={
                "confidence": 1.0,
                "reinforcement_count": self.reinforcement_count + 1,
            }
        )


# ---------------------------------------------------------------------------
# Genome — the collection of all known mutations
# ---------------------------------------------------------------------------


class Genome(BaseModel):
    """
    The full local genome: an HLC-ordered list of Mutations.

    This is persisted as append-only JSONL at ~/.selfhswarm/genome.jsonl.
    """

    node_id: str
    mutations: list[Mutation] = Field(default_factory=list)

    def sorted(self) -> list[Mutation]:
        """Return mutations sorted by HLC (oldest first)."""
        return sorted(self.mutations, key=lambda m: m.hlc)

    def for_client(self, client: AgentClient) -> list[Mutation]:
        """Return active (confidence > threshold) mutations for a client."""
        return [
            m
            for m in self.sorted()
            if (m.client == client or m.client == AgentClient.UNKNOWN)
            and m.confidence > 0.1
        ]

    def apply(self, mutation: Mutation) -> "Genome":
        """Append a new mutation, replacing any existing one with the same id."""
        existing_ids = {m.id for m in self.mutations}
        if mutation.id in existing_ids:
            updated = [m if m.id != mutation.id else mutation for m in self.mutations]
        else:
            updated = self.mutations + [mutation]
        return self.model_copy(update={"mutations": updated})

    def prune(self, min_confidence: float = 0.1) -> "Genome":
        """Remove low-confidence mutations."""
        pruned = [m for m in self.mutations if m.confidence >= min_confidence]
        return self.model_copy(update={"mutations": pruned})


# ---------------------------------------------------------------------------
# Streaming session — a single captured agent run
# ---------------------------------------------------------------------------


class StreamChunk(BaseModel):
    """One SSE or raw stream chunk as observed by the proxy."""

    index: int
    raw_hex: str  # hex of the raw bytes received from upstream
    parsed: dict[str, Any] | None = None  # parsed content if decoding succeeded
    anomalous: bool = False
    applied_mutation_id: str | None = None
    # NEW: populated when an anomaly is detected
    anomaly_type: str | None = None   # human-readable label (e.g. "bare_json_without_data_prefix")
    expected_hex: str | None = None   # hex of the repaired/patched version for the diff view


class Turn(BaseModel):
    """One request–response pair within an agent session."""

    index: int
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: dict[str, Any] | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_status: int = 200
    stream_chunks: list[StreamChunk] = Field(default_factory=list)
    token_usage: dict[str, int] = Field(default_factory=dict)
    duration_ms: float = 0.0
    anomalies_detected: int = 0
    mutations_applied: list[str] = Field(default_factory=list)


class Session(BaseModel):
    """A complete agent run captured by the proxy."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client: AgentClient = AgentClient.UNKNOWN
    node_id: str = ""
    started_at_hlc: HLCModel
    turns: list[Turn] = Field(default_factory=list)
    synthetic: bool = False  # True if this is a camouflage session
    # NEW: enriched by the proxy on CONNECT
    connect_target: str | None = None   # "api.anthropic.com:443"
    tls_established: bool = False
    provider: "ProviderProfile | None" = None


# ---------------------------------------------------------------------------
# Camouflage — synthetic chaos sessions
# ---------------------------------------------------------------------------


class ScenarioType(str, Enum):
    HALLUCINATED_TOOL = "hallucinated_tool"
    INFINITE_CONTEXT_GROWTH = "infinite_context_growth"
    IAM_CONSTRAINT_HALLUCINATION = "iam_constraint_hallucination"
    STREAM_MID_TRUNCATION = "stream_mid_truncation"
    PROVIDER_MODEL_SWAP = "provider_model_swap"
    REFLECTION_LOOP = "reflection_loop"
    CUSTOM = "custom"


class CamouflageSession(BaseModel):
    """A synthetic agent session for chaos engineering."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario: ScenarioType
    seed_session_id: str | None = None  # real session used as seed (optional)
    client: AgentClient
    injected_at: HLCModel
    turns: list[Turn] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# RNA Bus wire messages
# ---------------------------------------------------------------------------


class BusMessageType(str, Enum):
    HELLO = "hello"
    DELTA = "delta"
    PUSH = "push"
    BROADCAST = "broadcast"
    ACK = "ack"
    ERROR = "error"


class BusMessage(BaseModel):
    """Wire message for the RNA bus WebSocket protocol."""

    type: BusMessageType
    node_id: str
    payload: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------


class ProviderProfile(BaseModel):
    """Detected upstream LLM provider from the CONNECT hostname."""

    vendor: str    # e.g. "Anthropic"
    product: str   # e.g. "Claude"
    hostname: str  # e.g. "api.anthropic.com"


_HOSTNAME_TO_PROVIDER: dict[str, tuple[str, str]] = {
    "api.anthropic.com":                        ("Anthropic",   "Claude"),
    "api.openai.com":                           ("OpenAI",       "GPT"),
    "chatgpt.com":                              ("OpenAI",       "ChatGPT"),
    "generativelanguage.googleapis.com":        ("Google",       "Gemini"),
    "autopilot.googleapis.com":                 ("Google",       "Antigravity"),
    "api.moonshot.ai":                          ("Moonshot AI",  "Kimi"),
    "api2.cursor.sh":                           ("Cursor",       "Cursor"),
    "opencode.ai":                              ("OpenCode",     "OpenCode"),
    "api.hermes.ai":                            ("NousResearch", "Hermes"),
}


def detect_provider(hostname: str) -> ProviderProfile:
    """Return a ProviderProfile for the given CONNECT hostname."""
    # Exact match first
    if hostname in _HOSTNAME_TO_PROVIDER:
        vendor, product = _HOSTNAME_TO_PROVIDER[hostname]
        return ProviderProfile(vendor=vendor, product=product, hostname=hostname)
    # Suffix match (e.g. bedrock-runtime.us-east-1.amazonaws.com)
    for suffix, (vendor, product) in _HOSTNAME_TO_PROVIDER.items():
        if hostname.endswith(suffix):
            return ProviderProfile(vendor=vendor, product=product, hostname=hostname)
    return ProviderProfile(vendor="Unknown", product="Unknown", hostname=hostname)


# ---------------------------------------------------------------------------
# Live event bus types
# ---------------------------------------------------------------------------


class LiveEventType(str, Enum):
    SESSION_START    = "session_start"
    TURN_COMPLETE    = "turn_complete"
    ANOMALY_DETECTED = "anomaly_detected"
    MUTATION_DERIVED = "mutation_derived"
    SESSION_END      = "session_end"
    GENOME_UPDATE    = "genome_update"


class LiveEvent(BaseModel):
    """Emitted by the proxy onto the EventBus; forwarded to WebSocket clients."""

    type: LiveEventType
    session_id: str
    ts_ms: int = Field(default_factory=lambda: int(time.time() * 1000))
    payload: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


class ChunkReplay(BaseModel):
    """Single chunk result from a replay run."""

    index: int
    raw_hex: str
    patched_hex: str | None = None
    anomalous: bool
    anomaly_type: str | None = None
    mutation_id: str | None = None
    resolved: bool = False   # True if patch was applied successfully


class TurnReplay(BaseModel):
    turn_index: int
    chunks: list[ChunkReplay]
    anomalies_detected: int
    mutations_applied: int
    resolved: bool


class ReplayResult(BaseModel):
    session_id: str
    turn_results: list[TurnReplay]
    total_anomalies: int
    total_mutations_applied: int
    resolved: bool  # True if every anomaly was patched
