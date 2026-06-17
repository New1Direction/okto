"""Tests for the Camouflage fabricator."""

import pytest

from selfhswarm.camouflage.fabricator import Fabricator
from selfhswarm.hlc import HLCClock
from selfhswarm.models import AgentClient, CamouflageSession, ScenarioType


@pytest.fixture
def fab():
    return Fabricator(HLCClock("test"))


class TestFabricator:
    def test_fabricate_returns_camouflage_session(self, fab):
        s = fab.fabricate(ScenarioType.HALLUCINATED_TOOL, AgentClient.CLAUDE)
        assert isinstance(s, CamouflageSession)
        assert s.scenario == ScenarioType.HALLUCINATED_TOOL
        assert s.client == AgentClient.CLAUDE
        assert len(s.turns) >= 1

    def test_stream_truncation_produces_anomalous_chunks(self, fab):
        s = fab.fabricate(ScenarioType.STREAM_MID_TRUNCATION, AgentClient.CLAUDE)
        chunks = s.turns[-1].stream_chunks
        anomalous = [c for c in chunks if c.anomalous]
        assert len(anomalous) >= 1

    def test_provider_model_swap_changes_header(self, fab):
        s = fab.fabricate(ScenarioType.PROVIDER_MODEL_SWAP, AgentClient.CLAUDE)
        headers = s.turns[-1].response_headers
        assert "x-model-id" in headers

    def test_iam_hallucination_contains_arn(self, fab):

        s = fab.fabricate(ScenarioType.IAM_CONSTRAINT_HALLUCINATION, AgentClient.CLAUDE)
        chunk = s.turns[-1].stream_chunks[0]
        raw = bytes.fromhex(chunk.raw_hex)
        assert b"arn:aws" in raw

    def test_reflection_loop_injects_reflected_text(self, fab):
        s = fab.fabricate(
            ScenarioType.REFLECTION_LOOP,
            AgentClient.CLAUDE,
            previous_output="test output",
        )
        body = s.turns[-1].request_body or {}
        messages = body.get("messages", [])
        assert any("REFLECTED" in str(m) for m in messages)

    def test_infinite_context_growth_inflates_tokens(self, fab):
        s = fab.fabricate(ScenarioType.INFINITE_CONTEXT_GROWTH, AgentClient.CLAUDE)
        usage = s.turns[-1].token_usage
        assert usage.get("input_tokens", 0) > 1000

    def test_synthetic_flag_is_not_set(self, fab):
        """CamouflageSession is distinct from Session (no synthetic bool)."""
        s = fab.fabricate(ScenarioType.HALLUCINATED_TOOL, AgentClient.CLAUDE)
        # CamouflageSession does not have a 'synthetic' field — it's always synthetic
        assert not hasattr(s, "synthetic")
