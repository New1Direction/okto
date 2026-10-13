"""
Build a korg-ledger@v1 journal from one Okto capture.

Every event is a Korg ``AgentToolCall`` JournalEvent (agent_event_spec §1.2)
hash-chained per korg-ledger@v1, so ``korg-verify`` and the Korg web/JS
verifiers accept the file as-is. Event layout and causality (``triggered_by``
and ``causation_id``):

    1  user_prompt (synthesized root: session provenance)
    ├─ llm_inference  turn 0                 ← spine, §2a
    │   ├─ okto.anomaly  chunk k             ← one per anomalous chunk
    │   │   └─ okto.repair  mutation m       ← first application of each mutation
    │   └─ llm_inference  turn 1 …
    ├─ okto.replay   (current genome)        ← optional replay evidence
    │   └─ okto.replay_check  chunk k
    └─ okto.export_manifest                  ← schema, policy, counts, withheld data

All values are derived through ``boundary`` sanitizers and the finished
journal passes ``boundary.guard`` before a single byte is returned.
"""

from __future__ import annotations

import os
import pathlib
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import orjson

from selfhswarm import __version__
from selfhswarm.models import CamouflageSession, Genome, Mutation, Session
from selfhswarm.replay import replay_session

from . import boundary
from .boundary import (
    ACTOR_ID,
    EXPORT_SCHEMA,
    FINGERPRINT_SCHEME,
    REDACTION_POLICY,
    WITHHELD,
    Fingerprinter,
)
from .ledger import SPEC_VERSION, seal_chain, verify_chain, verify_dag

SOURCE_AGENT = f"agent:okto@{__version__}"
NIL_UUID = "00000000-0000-0000-0000-000000000000"
_ID_NAMESPACE = uuid.UUID("6f6b746f-6b6f-7267-8000-000000000001")  # "oktokorg"


@dataclass
class Capture:
    """A local capture loaded for export."""

    session: Session
    source_bytes: bytes
    scenario: str | None = None


def load_capture(path: pathlib.Path) -> Capture:
    """Load a proxy session or a ``okto fabricate`` camouflage session."""
    raw = pathlib.Path(path).read_bytes()
    data = orjson.loads(raw)
    if isinstance(data, dict) and "scenario" in data and "injected_at" in data:
        camo = CamouflageSession.model_validate(data)
        session = Session(
            id=camo.id,
            client=camo.client,
            started_at_hlc=camo.injected_at,
            turns=camo.turns,
            synthetic=True,
        )
        return Capture(session=session, source_bytes=raw, scenario=camo.scenario.value)
    return Capture(session=Session.model_validate(data), source_bytes=raw)


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{ms % 1000:03d}Z"
    )


@dataclass
class _Journal:
    session_ref: str
    base_ms: int
    events: list[dict] = field(default_factory=list)

    def _event_id(self, seq: int) -> str:
        return str(uuid.uuid5(_ID_NAMESPACE, f"{self.session_ref}:{seq}"))

    def add(
        self,
        tool: str,
        args: dict[str, Any],
        result: dict[str, Any],
        *,
        success: bool = True,
        duration_ms: int = 0,
        triggered_by: int | None,
        at_ms: int | None = None,
    ) -> int:
        seq = len(self.events) + 1
        physical = max(at_ms or self.base_ms, self.base_ms)
        self.events.append(
            {
                "schema_version": "1.0",
                "seq_id": seq,
                "metadata": {
                    "event_id": self._event_id(seq),
                    "correlation_id": str(uuid.uuid5(_ID_NAMESPACE, self.session_ref)),
                    "causation_id": self._event_id(triggered_by) if triggered_by else None,
                    "root_event_id": self._event_id(1),
                    "actor_id": ACTOR_ID,
                    "campaign_id": NIL_UUID,
                    # HLC: one physical stamp per phase, logical counter orders events.
                    "emitted_at": {"physical": physical, "logical": seq - 1, "actor_id": 1},
                    "branch_id": None,
                    "speculative": False,
                    "retry_count": 0,
                    "tier": "Telemetry",
                    "span_id": None,
                    "tags": {
                        "okto.export_schema": EXPORT_SCHEMA,
                        "okto.kind": boundary.TOOL_KIND[tool],
                        "okto.session_ref": self.session_ref,
                    },
                    "triggered_by": triggered_by,
                },
                "event": {
                    "event_type": "AgentToolCall",
                    "source_agent": SOURCE_AGENT,
                    "tool_name": tool,
                    "args": args,
                    "result": result,
                    "payload_refs": [],
                    "success": success,
                    "duration_ms": max(0, int(round(duration_ms))),
                    "timestamp": _iso(physical),
                },
            }
        )
        return seq


def _genome_fingerprint(fp: Fingerprinter, mutations: list[Mutation]) -> str:
    material = sorted(
        [m.id, m.scope.value, m.patch_type, m.pattern_hex, m.patch_hex] for m in mutations
    )
    return fp(orjson.dumps(material))


def build_journal(
    capture: Capture,
    fingerprinter: Fingerprinter,
    genome: list[Mutation] | None = None,
    *,
    replay: bool = True,
    exported_at_ms: int | None = None,
) -> tuple[list[dict], set[str]]:
    """
    Map *capture* onto Korg events. Returns (sealed events, published values):
    the second item lists source strings exported on purpose, for the guard.
    """
    session = capture.session
    fp = fingerprinter
    genome = list(genome or [])
    genome_by_id = {m.id: m for m in genome}
    published: set[str] = set()

    session_ref = fp(f"okto-session:{session.id}")
    base_ms = session.started_at_hlc.wall_ms
    journal = _Journal(session_ref=session_ref, base_ms=base_ms)

    # ── root: synthesized prompt carrying session provenance (spec §7.6) ──
    provider = session.provider
    vendor = provider.vendor if provider and provider.vendor in boundary.KNOWN_VENDORS else (
        "Unknown"
    )
    product = provider.product if provider and provider.product in boundary.KNOWN_PRODUCTS else (
        "Unknown"
    )
    root_result: dict[str, Any] = {
        "session_ref": session_ref,
        "client": session.client.value,
        "provider_vendor": vendor,
        "provider_product": product,
        "tls_established": session.tls_established,
        "synthetic": session.synthetic,
        "turn_count": len(session.turns),
        "okto_version": __version__,
    }
    host = boundary.provider_host(
        provider.hostname if provider else session.connect_target, vendor
    )
    if host:
        root_result["provider_host"] = host
        published.add(host)
    if session.node_id:
        root_result["capture_node"] = fp(f"okto-node:{session.node_id}")
    if capture.scenario:
        root_result["scenario"] = capture.scenario
    published.update({session.client.value, vendor, product})
    root = journal.add(
        "user_prompt",
        {"synthesized": True, "origin": "okto.session", "prompt_exported": False},
        root_result,
        triggered_by=None,
    )

    # ── turns, anomalies, repairs ──
    anomaly_events = repair_events = 0
    repaired_by: dict[str, int] = {}  # mutation id → applications
    first_anomaly_seq: dict[str, int] = {}
    parent = root
    for turn in session.turns:
        args: dict[str, Any] = {"turn_index": turn.index}
        body = turn.request_body if isinstance(turn.request_body, dict) else {}
        model = boundary.model_name(body.get("model"))
        if model:
            args["model"] = model
            published.add(model)
        if isinstance(body.get("stream"), bool):
            args["stream"] = body["stream"]
        anomalous = [(pos, c) for pos, c in enumerate(turn.stream_chunks) if c.anomalous]
        repaired_count = sum(1 for _, c in anomalous if c.applied_mutation_id)
        result: dict[str, Any] = {
            "status_code": turn.response_status,
            "chunk_count": len(turn.stream_chunks),
            "anomalies_detected": len(anomalous),
            "repairs_applied": repaired_count,
            **boundary.token_usage(turn.token_usage),
        }
        inference = journal.add(
            "llm_inference", args, result,
            success=200 <= turn.response_status < 400,
            duration_ms=turn.duration_ms,
            triggered_by=parent,
        )
        parent = inference

        for pos, chunk in anomalous:
            raw = bytes.fromhex(chunk.raw_hex)
            # A mutation can be "applied" without matching; report whether bytes changed.
            output_changed = bool(chunk.applied_mutation_id) and chunk.expected_hex not in (
                None, chunk.raw_hex
            )
            a_result: dict[str, Any] = {
                "repaired": chunk.applied_mutation_id is not None,
                "output_changed": output_changed,
                "raw_fingerprint": fp(raw),
                "raw_size_bytes": len(raw),
            }
            mutation_id = boundary.uuid_or_none(chunk.applied_mutation_id)
            if mutation_id:
                a_result["mutation_id"] = mutation_id
            if chunk.applied_mutation_id and chunk.expected_hex is not None:
                a_result["repaired_fingerprint"] = fp(bytes.fromhex(chunk.expected_hex))
            a_seq = journal.add(
                "okto.anomaly",
                {"turn_index": turn.index, "chunk_position": pos,
                 "anomaly_type": boundary.anomaly_type(chunk.anomaly_type)},
                a_result,
                success=a_result["repaired"],
                triggered_by=inference,
            )
            anomaly_events += 1
            if mutation_id:
                repaired_by[mutation_id] = repaired_by.get(mutation_id, 0) + 1
                first_anomaly_seq.setdefault(mutation_id, a_seq)

    for mutation_id, a_seq in first_anomaly_seq.items():
        mut = genome_by_id.get(mutation_id)
        r_args: dict[str, Any] = {"mutation_id": mutation_id}
        r_result: dict[str, Any] = {"in_genome": mut is not None,
                                    "applications": repaired_by[mutation_id]}
        if mut is None:
            anomaly_label = journal.events[a_seq - 1]["event"]["args"]["anomaly_type"]
            r_args["anomaly_type"] = anomaly_label
        else:
            r_args.update(
                anomaly_type=boundary.mutation_anomaly_type(mut),
                scope=mut.scope.value,
                patch_type=mut.patch_type,
            )
            r_result.update(
                confidence_bp=int(round(mut.confidence * 10_000)),
                reinforcement_count=mut.reinforcement_count,
                pattern_fingerprint=fp(mut.pattern),
                patch_fingerprint=fp(mut.patch),
                pattern_size_bytes=len(mut.pattern),
                patch_size_bytes=len(mut.patch),
            )
            if mut.source_node:
                r_result["origin_node"] = fp(f"okto-node:{mut.source_node}")
        journal.add("okto.repair", r_args, r_result, triggered_by=a_seq)
        repair_events += 1

    # ── replay evidence against the current genome ──
    replay_checks = 0
    export_ms = exported_at_ms if exported_at_ms is not None else base_ms
    if replay:
        client_mutations = Genome(node_id="", mutations=genome).for_client(session.client)
        rr = replay_session(session, client_mutations, node_id="korg-export")
        checks: list[tuple[dict, dict]] = []
        regressions = newly = 0
        unresolved: set[str] = set()
        all_match = True
        for turn, turn_replay in zip(session.turns, rr.turn_results, strict=True):
            for pos, (orig, rep) in enumerate(
                zip(turn.stream_chunks, turn_replay.chunks, strict=True)
            ):
                if not (orig.anomalous or rep.anomalous):
                    continue
                captured_repaired = orig.applied_mutation_id is not None
                if captured_repaired and not rep.resolved:
                    regressions += 1
                elif rep.resolved and not captured_repaired:
                    newly += 1
                if rep.anomalous and not rep.resolved:
                    unresolved.add(boundary.anomaly_type(rep.anomaly_type))
                if rep.resolved and captured_repaired:
                    matches = rep.patched_hex == orig.expected_hex
                else:
                    matches = rep.resolved == captured_repaired
                all_match = all_match and matches
                c_result: dict[str, Any] = {
                    "captured_repaired": captured_repaired,
                    "replay_repaired": rep.resolved,
                    "replay_output_changed": rep.resolved and rep.patched_hex != rep.raw_hex,
                    "matches_capture": matches,
                }
                if rep.resolved and rep.patched_hex is not None:
                    c_result["replay_output_fingerprint"] = fp(bytes.fromhex(rep.patched_hex))
                    # Mutations derived during replay are ephemeral; only genome ids are stable.
                    if rep.mutation_id in genome_by_id:
                        c_result["mutation_id"] = rep.mutation_id
                checks.append((
                    {"turn_index": turn.index, "chunk_position": pos,
                     "anomaly_type": boundary.anomaly_type(rep.anomaly_type or orig.anomaly_type)},
                    c_result,
                ))
        replay_seq = journal.add(
            "okto.replay",
            {"engine": "okto-state-machine",
             "genome_fingerprint": _genome_fingerprint(fp, client_mutations),
             "genome_mutations": len(client_mutations)},
            {"turns": len(rr.turn_results), "anomalies": rr.total_anomalies,
             "repaired": rr.total_mutations_applied, "resolved": rr.resolved,
             "regressions": regressions, "newly_repaired": newly,
             "matches_capture": all_match,
             "unresolved_anomaly_types": sorted(unresolved)},
            success=rr.resolved and regressions == 0,
            triggered_by=root,
            at_ms=export_ms,
        )
        for c_args, c_result in checks:
            journal.add(
                "okto.replay_check", c_args, c_result,
                success=c_result["matches_capture"],
                triggered_by=replay_seq,
                at_ms=export_ms,
            )
            replay_checks += 1

    journal.add(
        "okto.export_manifest",
        {"export_schema": EXPORT_SCHEMA, "korg_spec": SPEC_VERSION,
         "redaction_policy": REDACTION_POLICY, "fingerprint_scheme": FINGERPRINT_SCHEME,
         "fingerprint_key_id": fp.key_id, "source_fingerprint": fp(capture.source_bytes)},
        {"events": len(journal.events) + 1, "anomalies": anomaly_events,
         "repairs": repair_events, "replay_checks": replay_checks,
         "withheld": list(WITHHELD)},
        triggered_by=root,
        at_ms=export_ms,
    )
    return seal_chain(journal.events), published


def export_capture(
    capture: Capture,
    fingerprinter: Fingerprinter,
    genome: list[Mutation] | None = None,
    *,
    replay: bool = True,
    exported_at_ms: int | None = None,
) -> bytes:
    """Export *capture* as korg-ledger@v1 JSONL bytes. Raises BoundaryViolationError."""
    events, published = build_journal(
        capture, fingerprinter, genome, replay=replay, exported_at_ms=exported_at_ms
    )
    errors = verify_chain(events) + verify_dag(events)
    if errors:  # pragma: no cover - would be an exporter bug
        raise RuntimeError(f"exporter produced an invalid journal: {errors}")
    canaries = boundary.collect_canaries(capture.session, genome or [])
    canaries |= fingerprinter.canaries()
    return b"".join(boundary.guard(events, canaries, published))


def write_atomic(data: bytes, path: pathlib.Path) -> None:
    """Write *data* to *path* (mode 0600) via a same-directory temp file."""
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        pathlib.Path(tmp).unlink(missing_ok=True)
        raise


def verify_export(data: bytes) -> list[str]:
    """
    Check an export file before handing it to Korg: JSONL parse, hash chain,
    causal DAG, structural allowlist, and secret scan (canaries need the
    source capture and are checked at export time).
    """
    events: list[Any] = []
    errors: list[str] = []
    for n, line in enumerate(data.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(orjson.loads(line))
        except orjson.JSONDecodeError:
            errors.append(f"line {n}: not valid JSON")
            continue
        errors.extend(
            f"line {n}: {e}" for e in boundary.check_line(line.decode("utf-8", "replace"))
        )
    if not events:
        return errors + ["no events"]
    errors.extend(verify_chain(events))
    errors.extend(verify_dag(events))
    for e in events:
        errors.extend(boundary.check_structure(e))
    last = events[-1]
    tool = last.get("event", {}).get("tool_name") if isinstance(last, dict) else None
    if tool != "okto.export_manifest":
        errors.append("last event must be okto.export_manifest (export truncated?)")
    elif last["event"]["result"].get("events") != len(events):
        errors.append("manifest event count does not match the file (events added/removed)")
    return errors
