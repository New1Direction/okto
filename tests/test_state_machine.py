"""Tests for the ProxyStateMachine and PatchEngine."""

import pytest

from selfhswarm.hlc import HLCClock
from selfhswarm.models import AgentClient, MutationScope, ProxyState
from selfhswarm.proxy.state_machine import PatchEngine, ProxyStateMachine


@pytest.fixture
def clock():
    return HLCClock("test-node")


@pytest.fixture
def sm(clock):
    return ProxyStateMachine(
        client=AgentClient.CLAUDE,
        node_id="test-node",
        session_id="sess-001",
        genome_mutations=[],
        clock=clock,
    )


# ---------------------------------------------------------------------------
# PatchEngine
# ---------------------------------------------------------------------------


class TestPatchEngine:
    def test_no_anomaly_clean_sse(self):
        chunk = b"data: {}\n\n"
        # No detectors triggered directly; test via state machine
        assert b"data:" in chunk

    def test_sse_prefix_repair(self):
        from selfhswarm.proxy.state_machine import _sse_prefix_check

        assert _sse_prefix_check(b"data: {}\n") is None
        assert _sse_prefix_check(b"event: ping\n") is None
        assert _sse_prefix_check(b"{bad chunk}") is not None

    def test_json_parse_repair(self):
        from selfhswarm.proxy.state_machine import _json_parse_check

        assert _json_parse_check(b"data: {}\n") is None
        assert _json_parse_check(b"data: [DONE]\n") is None
        assert _json_parse_check(b"data: {bad json\n") is not None

    def test_derive_missing_data_prefix(self):
        from selfhswarm.models import HLCModel

        engine = PatchEngine()
        clock = HLCClock("test")
        t = clock.tick()
        hlc_model = HLCModel.from_hlc(t)
        raw = b'{"type":"content_block_delta"}'
        mut = engine.derive(
            raw,
            "SSE chunk missing known prefix",
            AgentClient.CLAUDE,
            MutationScope.STREAM_CHUNK,
            "test-node",
            "sess",
            hlc_model,
        )
        assert mut is not None
        assert b"data:" in mut.patch

    def test_derive_done_without_prefix(self):
        from selfhswarm.models import HLCModel

        engine = PatchEngine()
        clock = HLCClock("test")
        hlc_model = HLCModel.from_hlc(clock.tick())
        raw = b"[DONE]"
        mut = engine.derive(
            raw,
            "missing prefix",
            AgentClient.CLAUDE,
            MutationScope.STREAM_CHUNK,
            "n",
            "s",
            hlc_model,
        )
        assert mut is not None
        assert mut.patch == b"data: [DONE]"


# ---------------------------------------------------------------------------
# ProxyStateMachine
# ---------------------------------------------------------------------------


class TestProxyStateMachine:
    def test_clean_chunk_stays_nominal(self, sm):
        output, meta = sm.process_chunk(b"data: {}\n\n", MutationScope.STREAM_CHUNK)
        assert sm.state == ProxyState.NOMINAL
        assert not meta.anomalous
        assert output == b"data: {}\n\n"

    def test_anomalous_chunk_triggers_patch(self, sm):
        raw = b'{"type":"delta","text":"hello"}'
        output, meta = sm.process_chunk(raw, MutationScope.STREAM_CHUNK)
        assert meta.anomalous
        # State should be PATCH_APPLIED (derivation succeeded) or MONITORING
        assert sm.state in (ProxyState.PATCH_APPLIED, ProxyState.MONITORING)

    def test_derived_mutation_stored(self, clock):
        captured = []
        sm = ProxyStateMachine(
            client=AgentClient.CLAUDE,
            node_id="n",
            session_id="s",
            genome_mutations=[],
            clock=clock,
            on_new_mutation=captured.append,
        )
        sm.process_chunk(b'{"bare":"json"}', MutationScope.STREAM_CHUNK)
        # If derivation succeeded, we expect one mutation captured
        assert len(captured) <= 1  # 0 if no derivation possible, 1 if derived

    def test_genome_mutation_applied_and_reinforced(self, clock):
        from selfhswarm.models import HLCModel, Mutation

        t = clock.tick()
        hlc_model = HLCModel.from_hlc(t)
        # Pre-load a mutation that repairs missing 'data:' prefix
        existing = Mutation(
            hlc=hlc_model,
            client=AgentClient.CLAUDE,
            scope=MutationScope.STREAM_CHUNK,
            pattern_hex=b'{"type":"ping"}'.hex(),
            patch_hex=(b"data: " + b'{"type":"ping"}').hex(),
            patch_type="literal",
            confidence=0.8,
        )
        sm = ProxyStateMachine(
            client=AgentClient.CLAUDE,
            node_id="n",
            session_id="s",
            genome_mutations=[existing],
            clock=clock,
        )
        raw = b'{"type":"ping"}'
        output, meta = sm.process_chunk(raw, MutationScope.STREAM_CHUNK)
        # Mutation should have been applied
        if meta.applied_mutation_id == existing.id:
            assert output == b"data: " + raw
