"""
Okto → Korg boundary: korg-ledger@v1 conformance, redaction, and tamper checks.

The redaction tests plant credentials and sensitive payloads in every part of
a capture Okto stores locally, export it, and assert that no form of them
(raw, hex, base64, URL-encoded, unkeyed SHA-256) reaches the Korg file.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import urllib.parse

import orjson
import pytest
from click.testing import CliRunner

from selfhswarm.camouflage.fabricator import Fabricator
from selfhswarm.cli import main
from selfhswarm.hlc import HLCClock
from selfhswarm.korg import (
    BoundaryViolationError,
    Capture,
    Fingerprinter,
    boundary,
    build_journal,
    canonicalize,
    chain_hash,
    export_capture,
    load_capture,
    verify_chain,
    verify_export,
)
from selfhswarm.korg.ledger import GENESIS_HASH, seal_chain
from selfhswarm.models import (
    AgentClient,
    HLCModel,
    Mutation,
    MutationScope,
    ScenarioType,
    Session,
    StreamChunk,
    Turn,
    detect_provider,
)
from selfhswarm.proxy.state_machine import ProxyStateMachine

VECTORS = pathlib.Path(__file__).parent / "fixtures" / "korg-ledger-v1"
KEY = bytes(range(32))

SECRETS = {
    "bearer": "sk-ant-oat01-Zq8hBEARERtokenVALUE00001",
    "x_api_key": "sk-ant-api03-XAPIKEYvalue0000000002",
    "goog_key": "AIzaSyD-GOOGLEkeyVALUE000000000000003",
    "cookie": "sessionid=COOKIEvalue0000000004",
    "set_cookie": "__cf_bm=SETCOOKIEvalue000000005",
    "proxy_auth": "Basic cHJveHk6UFJPWFlwYXNzd29yZA==",
    "system_prompt": "CONFIDENTIAL: internal escalation runbook v7",
    "user_message": "deploy with AKIAIOSFODNN7EXAMPLE please",
    "tool_payload": "-----BEGIN RSA PRIVATE KEY-----MIIEvQIBADAN",
    "stream_text": "the database password is hunter2-correct-horse",
    "bare_chunk_text": "ghp_STREAMEDgithubTOKEN000000000000000006",
    "broken_chunk_text": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SIGNATUREsig",
    "session_id": "5e55104e-0000-4000-8000-5ec2e7000001",
    "node_id": "node-PRIVATE-HOSTNAME-laptop-0007",
}

SSE_CHUNKS = [
    # clean frame, contains a secret in model output
    b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"'
    + SECRETS["stream_text"].encode() + b'"}}\n\n',
    # bare JSON → bare_json_without_data_prefix, derives a literal mutation over these bytes
    b'{"type":"content_block_delta","delta":{"text":"' + SECRETS["bare_chunk_text"].encode()
    + b'"}}',
    # truncated JSON → malformed_json_in_sse_frame
    b'data: {"type":"content_block_delta","delta":{"text":"'
    + SECRETS["broken_chunk_text"].encode(),
    b"data: [DONE]\n\n",
]


def _secret_capture() -> tuple[Capture, list[Mutation]]:
    clock = HLCClock(SECRETS["node_id"])
    session = Session(
        id=SECRETS["session_id"],
        client=AgentClient.CLAUDE,
        node_id=SECRETS["node_id"],
        started_at_hlc=HLCModel(wall_ms=1_781_405_728_591, counter=0, node_id="n"),
        connect_target="api.anthropic.com:443",
        tls_established=True,
        provider=detect_provider("api.anthropic.com"),
    )
    derived: list[Mutation] = []
    sm = ProxyStateMachine(
        AgentClient.CLAUDE, SECRETS["node_id"], session.id, [], clock,
        on_new_mutation=derived.append,
    )
    turns = []
    for index in range(2):
        turn = Turn(
            index=index,
            request_headers={
                "host": "api.anthropic.com",
                "authorization": f"Bearer {SECRETS['bearer']}",
                "x-api-key": SECRETS["x_api_key"],
                "x-goog-api-key": SECRETS["goog_key"],
                "cookie": SECRETS["cookie"],
                "proxy-authorization": SECRETS["proxy_auth"],
                "anthropic-version": "2023-06-01",
            },
            request_body={
                "model": "claude-opus-4-6",
                "stream": True,
                "system": SECRETS["system_prompt"],
                "messages": [
                    {"role": "user", "content": SECRETS["user_message"]},
                    {"role": "user", "content": [
                        {"type": "tool_result", "content": SECRETS["tool_payload"]}
                    ]},
                ],
            },
            response_headers={"set-cookie": SECRETS["set_cookie"],
                              "content-type": "text/event-stream"},
            response_status=200,
            token_usage={"input_tokens": 1200 + index, "output_tokens": 58,
                         "x-secret-usage": 9},
            duration_ms=412.7,
        )
        for raw in SSE_CHUNKS:
            _, meta = sm.process_chunk(raw, MutationScope.STREAM_CHUNK)
            turn.stream_chunks.append(meta)
        turn.anomalies_detected = sum(c.anomalous for c in turn.stream_chunks)
        turns.append(turn)
    session.turns = turns
    raw_bytes = orjson.dumps(session.model_dump())
    return Capture(session=session, source_bytes=raw_bytes), derived


def _events(data: bytes) -> list[dict]:
    return [json.loads(line) for line in data.splitlines() if line.strip()]


def _forms(secret: str) -> list[str]:
    raw = secret.encode()
    return [
        secret,
        raw.hex(),
        raw.hex().upper(),
        base64.b64encode(raw).decode().rstrip("="),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        urllib.parse.quote(secret, safe=""),
        json.dumps(secret)[1:-1],
    ]


# ---------------------------------------------------------------------------
# korg-ledger@v1 conformance (frozen vectors from the Korg repo)
# ---------------------------------------------------------------------------


class TestKorgLedgerConformance:
    def _read(self, name: str) -> list[dict]:
        return [json.loads(line) for line in (VECTORS / name).read_text().splitlines() if line]

    def test_canonicalization_matches_spec_example(self):
        value = {"z": [3, 2], "a": {"y": 1, "x": 2}}
        assert canonicalize(value) == b'{"a":{"x":2,"y":1},"z":[3,2]}'
        assert canonicalize({"k": "é"}) == b'{"k":"\\u00e9"}'

    def test_reproduces_frozen_tips_and_flags_tampering(self):
        manifest = json.loads((VECTORS / "conformance.json").read_text())
        assert manifest["spec_version"] == "korg-ledger@v1"
        for vector in manifest["vectors"]:
            events = self._read(vector["file"])
            key = vector["key"].encode() if vector["key"] else None
            errors = verify_chain(events, key)
            if vector["verify"] == "intact":
                assert errors == [], vector["file"]
                assert chain_hash(events[-1], key) == vector["tip_entry_hash"]
                if key:  # keyed chain must fail without the key
                    assert verify_chain(events) != []
            else:
                assert any(vector["error_contains"] in e for e in errors), (vector, errors)

    def test_seal_chain_reproduces_frozen_tip_from_unhashed_events(self):
        events = self._read("basic-intact.jsonl")
        stripped = [{k: v for k, v in e.items() if k not in ("prev_hash", "entry_hash")}
                    for e in events]
        sealed = seal_chain(stripped)
        assert sealed[0]["prev_hash"] == GENESIS_HASH
        assert sealed[-1]["entry_hash"] == events[-1]["entry_hash"]

    @pytest.mark.parametrize("value", [1.5, 2**53, float("nan")])
    def test_rejects_numbers_korg_verifiers_disagree_on(self, value):
        with pytest.raises(ValueError):
            canonicalize({"n": value})


# ---------------------------------------------------------------------------
# Export shape and causality
# ---------------------------------------------------------------------------


class TestExportShape:
    @pytest.fixture
    def exported(self):
        capture, derived = _secret_capture()
        data = export_capture(
            capture, Fingerprinter(KEY), derived, exported_at_ms=1_781_500_000_000
        )
        return capture, derived, data

    def test_journal_is_valid_korg_ledger_and_passes_export_verifier(self, exported):
        _, _, data = exported
        events = _events(data)
        assert verify_export(data) == []
        assert [e["seq_id"] for e in events] == list(range(1, len(events) + 1))
        for e in events:
            assert e["schema_version"] == "1.0"
            assert e["event"]["event_type"] == "AgentToolCall"
            assert e["event"]["source_agent"].startswith("agent:okto@")
            assert e["event"]["payload_refs"] == []
            for part in ("args", "result"):
                for v in e["event"][part].values():
                    assert len(canonicalize(v)) <= boundary.MAX_FIELD_BYTES

    def test_causal_graph_follows_korg_spine_rules(self, exported):
        _, _, data = exported
        events = _events(data)
        by_seq = {e["seq_id"]: e for e in events}
        tool = {s: e["event"]["tool_name"] for s, e in by_seq.items()}
        parent = {s: e["metadata"]["triggered_by"] for s, e in by_seq.items()}

        assert [s for s, p in parent.items() if p is None] == [1]
        assert tool[1] == "user_prompt" and by_seq[1]["event"]["args"]["synthesized"] is True
        inferences = [s for s in by_seq if tool[s] == "llm_inference"]
        # §2a: each inference hangs off the previous inference, the first off the root.
        assert [parent[s] for s in inferences] == [1, inferences[0]]
        for s, e in by_seq.items():
            if parent[s] is not None:
                assert e["metadata"]["causation_id"] == by_seq[parent[s]]["metadata"]["event_id"]
            if tool[s] == "okto.anomaly":
                assert tool[parent[s]] == "llm_inference"
                turn_index = e["event"]["args"]["turn_index"]
                assert by_seq[parent[s]]["event"]["args"]["turn_index"] == turn_index
            if tool[s] == "okto.repair":
                assert tool[parent[s]] == "okto.anomaly"
            if tool[s] == "okto.replay_check":
                assert tool[parent[s]] == "okto.replay"
        assert tool[len(events)] == "okto.export_manifest"

    def test_summaries_reflect_the_capture(self, exported):
        capture, derived, data = exported
        events = _events(data)
        anomalies = [e for e in events if e["event"]["tool_name"] == "okto.anomaly"]
        # 2 turns x (bare JSON + truncated JSON) — the clean frames are not reported.
        assert [(a["event"]["args"]["turn_index"], a["event"]["args"]["chunk_position"],
                 a["event"]["args"]["anomaly_type"]) for a in anomalies] == [
            (0, 1, "bare_json_without_data_prefix"),
            (0, 2, "malformed_json_in_sse_frame"),
            (1, 1, "bare_json_without_data_prefix"),
            (1, 2, "malformed_json_in_sse_frame"),
        ]
        fp = Fingerprinter(KEY)
        first = anomalies[0]["event"]["result"]
        assert first["raw_fingerprint"] == fp(SSE_CHUNKS[1])
        assert first["repaired_fingerprint"] == fp(b"data: " + SSE_CHUNKS[1])
        assert first["output_changed"] is True
        # The truncated frame is "applied" but its bytes do not change: say so.
        assert anomalies[1]["event"]["result"]["output_changed"] is False

        inference = next(e for e in events if e["event"]["tool_name"] == "llm_inference")
        assert inference["event"]["args"] == {"turn_index": 0, "model": "claude-opus-4-6",
                                              "stream": True}
        assert inference["event"]["result"]["input_tokens"] == 1200
        assert "x-secret-usage" not in inference["event"]["result"]
        assert inference["event"]["duration_ms"] == 413

        repairs = [e for e in events if e["event"]["tool_name"] == "okto.repair"]
        assert len(repairs) == 1 and repairs[0]["event"]["result"]["applications"] == 4
        assert repairs[0]["event"]["args"]["mutation_id"] == derived[0].id
        assert repairs[0]["event"]["result"]["confidence_bp"] == 10_000

        manifest = events[-1]["event"]
        assert manifest["result"]["events"] == len(events)
        assert manifest["args"]["fingerprint_key_id"] == fp.key_id
        assert "request_headers" in manifest["result"]["withheld"]

    def test_export_is_deterministic_and_key_scoped(self):
        capture, derived = _secret_capture()
        a = export_capture(capture, Fingerprinter(KEY), derived, exported_at_ms=1)
        b = export_capture(capture, Fingerprinter(KEY), derived, exported_at_ms=1)
        c = export_capture(capture, Fingerprinter(bytes([7]) * 32), derived, exported_at_ms=1)
        assert a == b
        fps_a = {v for e in _events(a) for v in e["event"]["result"].values()
                 if isinstance(v, str) and v.startswith("hmac-sha256:")}
        fps_c = {v for e in _events(c) for v in e["event"]["result"].values()
                 if isinstance(v, str) and v.startswith("hmac-sha256:")}
        assert fps_a and not fps_a & fps_c


# ---------------------------------------------------------------------------
# Redaction: nothing sensitive crosses
# ---------------------------------------------------------------------------


class TestRedaction:
    def test_no_secret_or_payload_crosses_in_any_encoding(self):
        capture, derived = _secret_capture()
        data = export_capture(capture, Fingerprinter(KEY), derived).decode("ascii")
        for name, secret in SECRETS.items():
            for form in _forms(secret):
                assert form not in data, f"{name} leaked as {form[:12]}…"
        for name in ("authorization", "x-api-key", "cookie", "set-cookie", "x-goog-api-key"):
            assert f'"{name}"' not in data.lower()

    def test_no_raw_bytes_unkeyed_digests_or_key_material(self):
        capture, derived = _secret_capture()
        data = export_capture(capture, Fingerprinter(KEY), derived).decode("ascii")
        assert KEY.hex() not in data
        for raw in SSE_CHUNKS + [m.pattern for m in derived] + [m.patch for m in derived]:
            assert raw.hex() not in data
            # Unkeyed digests would let a Korg reader confirm guessed content.
            assert hashlib.sha256(raw).hexdigest() not in data
        for m in derived:
            assert m.description not in data  # embeds raw chunk bytes

    def test_secret_shaped_model_name_is_dropped(self):
        capture, derived = _secret_capture()
        capture.session.turns[0].request_body["model"] = SECRETS["x_api_key"]
        data = export_capture(capture, Fingerprinter(KEY), derived).decode("ascii")
        assert SECRETS["x_api_key"] not in data
        inference = next(e for e in _events(data.encode())
                         if e["event"]["tool_name"] == "llm_inference")
        assert "model" not in inference["event"]["args"]

    def test_unknown_provider_host_is_not_exported(self):
        capture, derived = _secret_capture()
        capture.session.provider = detect_provider("llm-gateway.corp.internal")
        capture.session.connect_target = "llm-gateway.corp.internal:443"
        data = export_capture(capture, Fingerprinter(KEY), derived).decode("ascii")
        assert "corp.internal" not in data
        assert _events(data.encode())[0]["event"]["result"]["provider_vendor"] == "Unknown"


class TestBoundaryGuard:
    def _journal(self):
        capture, derived = _secret_capture()
        events, published = build_journal(capture, Fingerprinter(KEY), derived)
        canaries = boundary.collect_canaries(capture.session, derived)
        return events, published, canaries

    def test_extra_field_is_blocked(self):
        events, published, canaries = self._journal()
        events[1]["event"]["args"]["request_headers"] = {"accept": "*/*"}
        seal_chain(events)
        with pytest.raises(BoundaryViolationError, match="not in export allowlist"):
            boundary.guard(events, canaries, published)

    def test_float_and_unknown_tool_are_blocked(self):
        events, published, canaries = self._journal()
        events[1]["event"]["result"]["status_code"] = 200.0
        events[2]["event"]["tool_name"] = "okto.raw_dump"
        with pytest.raises(BoundaryViolationError) as exc:
            boundary.guard(events, canaries, published)
        assert "status_code" in str(exc.value) and "okto.raw_dump" in str(exc.value)

    def test_canary_in_an_allowed_field_is_blocked_without_echoing_it(self):
        events, published, canaries = self._journal()
        leaked = SECRETS["system_prompt"][:40]
        assert any(leaked in c for c in canaries)
        events[1]["event"]["args"]["model"] = "x"  # valid kind
        events[1]["metadata"]["tags"]["okto.session_ref"] = leaked
        with pytest.raises(BoundaryViolationError) as exc:
            boundary.guard(events, [leaked], published)
        assert leaked not in str(exc.value)

    def test_canary_check_catches_hex_encoded_payloads(self):
        events, published, _ = self._journal()
        canary = "internal-only-value-123"
        events[0]["event"]["result"]["okto_version"] = "0.1.0"
        # Smuggle the hex form through a string field that skips kind checks: the tags.
        events[0]["metadata"]["tags"]["okto.kind"] = canary.encode().hex()
        lines_ok = boundary.check_line(json.dumps(events[0]), [canary], published)
        assert any("leaked" in e for e in lines_ok)

    @pytest.mark.parametrize("secret", [
        SECRETS["bearer"], SECRETS["goog_key"], "Bearer abcdefgh12345678",
        SECRETS["broken_chunk_text"], "AKIAIOSFODNN7EXAMPLE", SECRETS["tool_payload"],
        '"api_key": "x"', "https://user:pass@host/x", "ab" * 40,
    ])
    def test_secret_scanner_flags_credential_shapes(self, secret):
        assert boundary.check_line(json.dumps({"v": secret})) != []

    def test_secret_scanner_accepts_a_real_export(self):
        capture, derived = _secret_capture()
        data = export_capture(capture, Fingerprinter(KEY), derived)
        for line in data.splitlines():
            assert boundary.check_line(line.decode()) == []


# ---------------------------------------------------------------------------
# Replay evidence
# ---------------------------------------------------------------------------


class TestReplayEvidence:
    def test_replay_reports_regression_when_genome_lost_the_fix(self):
        # Captured with a since-removed genome mutation; no rule can be derived
        # for this chunk on replay, so the repair regresses.
        raw = b"event-stream garbage frame"
        mid = "0294fa1d-8b7e-4017-935d-37db72e7fa07"
        session = Session(
            id="s-regress", client=AgentClient.CLAUDE,
            started_at_hlc=HLCModel(wall_ms=1000, counter=0, node_id="n"),
            turns=[Turn(index=0, stream_chunks=[
                StreamChunk(index=0, raw_hex=b"data: {}\n\n".hex()),
                StreamChunk(index=0, raw_hex=raw.hex(), anomalous=True,
                            anomaly_type="bare_json_without_data_prefix",
                            applied_mutation_id=mid, expected_hex=(b"data: " + raw).hex()),
            ])],
        )
        capture = Capture(session=session, source_bytes=b"{}")
        events = _events(export_capture(capture, Fingerprinter(KEY), []))
        replay = next(e for e in events if e["event"]["tool_name"] == "okto.replay")
        assert replay["event"]["result"] == {
            "turns": 1, "anomalies": 1, "repaired": 0, "resolved": False,
            "regressions": 1, "newly_repaired": 0, "matches_capture": False,
            "unresolved_anomaly_types": ["bare_json_without_data_prefix"],
        }
        assert replay["event"]["success"] is False
        check = next(e for e in events if e["event"]["tool_name"] == "okto.replay_check")
        assert check["event"]["args"]["chunk_position"] == 1
        assert check["event"]["result"]["captured_repaired"] is True
        assert check["event"]["result"]["replay_repaired"] is False
        repair = next(e for e in events if e["event"]["tool_name"] == "okto.repair")
        assert repair["event"]["result"] == {"in_genome": False, "applications": 1}

    def test_no_replay_omits_replay_events(self):
        capture, derived = _secret_capture()
        events = _events(export_capture(capture, Fingerprinter(KEY), derived, replay=False))
        tools = {e["event"]["tool_name"] for e in events}
        assert not tools & {"okto.replay", "okto.replay_check"}
        assert events[-1]["event"]["result"]["replay_checks"] == 0


# ---------------------------------------------------------------------------
# Tamper detection on an existing export
# ---------------------------------------------------------------------------


class TestVerifyExport:
    @pytest.fixture
    def lines(self) -> list[bytes]:
        capture, derived = _secret_capture()
        return export_capture(capture, Fingerprinter(KEY), derived).splitlines(keepends=True)

    def test_edited_event_is_localized(self, lines):
        event = json.loads(lines[1])
        event["event"]["result"]["anomalies_detected"] = 0
        lines[1] = json.dumps(event).encode() + b"\n"
        assert any("seq 2: entry_hash mismatch" in e for e in verify_export(b"".join(lines)))

    def test_truncated_export_is_detected(self, lines):
        errors = verify_export(b"".join(lines[:-1]))
        assert any("export_manifest" in e for e in errors)

    def test_resealed_injection_is_still_rejected(self, lines):
        events = [json.loads(line) for line in lines]
        events[1]["event"]["result"]["request_body"] = SECRETS["system_prompt"]
        seal_chain(events)
        data = b"".join(json.dumps(e).encode() + b"\n" for e in events)
        assert verify_chain(_events(data)) == []  # chain alone would accept it
        assert any("not in export allowlist" in e for e in verify_export(data))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestKorgCli:
    def _write_capture(self, tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        capture, derived = _secret_capture()
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        (sessions / f"{capture.session.id}.jsonl").write_bytes(capture.source_bytes)
        genome = tmp_path / "genome.jsonl"
        genome.write_bytes(b"".join(orjson.dumps(m.model_dump()) + b"\n" for m in derived))
        return sessions, genome

    def test_export_by_id_then_verify(self, tmp_path):
        sessions, genome = self._write_capture(tmp_path)
        out = tmp_path / "korg" / "out.jsonl"
        key = tmp_path / "k.key"
        runner = CliRunner()
        result = runner.invoke(main, [
            "korg", "export", SECRETS["session_id"], "--session-dir", str(sessions),
            "--genome", str(genome), "--key-file", str(key), "-o", str(out),
        ])
        assert result.exit_code == 0, result.output
        assert out.stat().st_mode & 0o777 == 0o600
        assert key.stat().st_mode & 0o777 == 0o600 and len(key.read_bytes()) == 32
        data = out.read_text()
        assert SECRETS["bearer"] not in data and SECRETS["stream_text"] not in data
        assert any(e["event"]["tool_name"] == "okto.repair" for e in _events(out.read_bytes()))

        ok = runner.invoke(main, ["korg", "verify", str(out)])
        assert ok.exit_code == 0, ok.output
        out.write_text(data.replace('"repairs_applied":2', '"repairs_applied":9', 1))
        bad = runner.invoke(main, ["korg", "verify", str(out)])
        assert bad.exit_code == 1 and "entry_hash mismatch" in bad.output

    def test_rejects_path_traversal_session_id(self, tmp_path):
        result = CliRunner().invoke(main, [
            "korg", "export", "../../etc/passwd", "--session-dir", str(tmp_path),
        ])
        assert result.exit_code != 0
        assert "session id" in result.output

    def test_fails_closed_and_writes_nothing(self, tmp_path):
        capture, _ = _secret_capture()
        # A payload string identical to an exported value trips the canary scan.
        capture.session.turns[0].request_body["note"] = "okto-state-machine"
        src = tmp_path / "s.jsonl"
        src.write_bytes(orjson.dumps(capture.session.model_dump()))
        out = tmp_path / "out.jsonl"
        result = CliRunner().invoke(main, [
            "korg", "export", str(src), "--genome", str(tmp_path / "none.jsonl"),
            "--key-file", str(tmp_path / "k.key"), "-o", str(out),
        ])
        assert result.exit_code != 0
        assert "blocked at the Korg boundary" in result.output
        assert not out.exists() and not list(tmp_path.glob(".out.jsonl.*"))

    def test_exports_fabricated_chaos_session(self, tmp_path):
        camo = Fabricator(HLCClock("t")).fabricate(
            ScenarioType.STREAM_MID_TRUNCATION, AgentClient.CLAUDE
        )
        src = tmp_path / "chaos.json"
        src.write_bytes(orjson.dumps(camo.model_dump()))
        capture = load_capture(src)
        data = export_capture(capture, Fingerprinter(KEY), [])
        root = _events(data)[0]["event"]["result"]
        assert root["synthetic"] is True and root["scenario"] == "stream_mid_truncation"
        assert verify_export(data) == []
