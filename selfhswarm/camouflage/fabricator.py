"""
Layer 2 — Camouflage Engine: synthetic session fabrication.

The fabricator takes an optional seed session (real captured trace)
and applies a scenario transform to produce a synthetic session that
is statistically indistinguishable from real traffic.

The resulting CamouflageSession can be:
  1. Replayed via the proxy (the proxy serves synthetic responses)
  2. Saved as a trace for documentation / sharing
  3. Used to stress-test downstream agent logic
"""

from __future__ import annotations

import random
import uuid
from typing import Any

import orjson

from selfhswarm.hlc import HLCClock
from selfhswarm.models import (
    AgentClient,
    CamouflageSession,
    HLCModel,
    ScenarioType,
    Session,
    StreamChunk,
    Turn,
)


# ---------------------------------------------------------------------------
# Scenario implementations
# ---------------------------------------------------------------------------


def _scenario_hallucinated_tool(turn: Turn) -> Turn:
    """
    Inject a malformed tool_use result into a response turn.

    The tool returns JSON with a missing required field, triggering
    the agent's error recovery path.
    """
    bad_result = {
        "type": "tool_result",
        "tool_use_id": f"toolu_{uuid.uuid4().hex[:12]}",
        # 'content' field is intentionally missing
        "is_error": False,
        "extra_poison": "{{UNDEFINED_VARIABLE}}",
    }
    # Overwrite the last stream chunk with the bad payload
    chunk = StreamChunk(
        index=len(turn.stream_chunks),
        raw_hex=f"data: {orjson.dumps(bad_result).decode()}\n\n".encode().hex(),
        anomalous=True,
    )
    return turn.model_copy(update={"stream_chunks": turn.stream_chunks + [chunk]})


def _scenario_stream_mid_truncation(turn: Turn) -> Turn:
    """
    Cut the SSE stream at byte 4096 then resume with a corrupted delta.

    This simulates provider-side stream interruptions.
    """
    truncation_marker = b"\r\n\r\n"  # abrupt end
    resume = b'data: {"type":"content_block_delta","corrupted":true}\n\n'
    chunks = [
        StreamChunk(
            index=0,
            raw_hex=(b"data: " + b"A" * 4096).hex(),
            anomalous=False,
        ),
        StreamChunk(
            index=1,
            raw_hex=truncation_marker.hex(),
            anomalous=True,
        ),
        StreamChunk(
            index=2,
            raw_hex=resume.hex(),
            anomalous=True,
        ),
        StreamChunk(
            index=3,
            raw_hex=b"data: [DONE]\n\n".hex(),
            anomalous=False,
        ),
    ]
    return turn.model_copy(update={"stream_chunks": chunks})


def _scenario_provider_model_swap(turn: Turn, new_model: str = "claude-opus-5-0") -> Turn:
    """
    Mid-session, response headers claim a different model ID.

    This tests whether the agent validates or trusts the model field.
    """
    headers = dict(turn.response_headers)
    headers["x-model-id"] = new_model
    headers["anthropic-model"] = new_model
    return turn.model_copy(
        update={
            "response_headers": headers,
            "stream_chunks": [
                StreamChunk(
                    index=0,
                    raw_hex=orjson.dumps(
                        {
                            "type": "message_start",
                            "message": {
                                "id": f"msg_{uuid.uuid4().hex[:12]}",
                                "model": new_model,
                                "role": "assistant",
                                "content": [],
                                "usage": {"input_tokens": 0, "output_tokens": 0},
                            },
                        }
                    ).hex(),
                    anomalous=False,
                )
            ],
        }
    )


def _scenario_reflection_loop(turn: Turn, previous_output: str = "") -> Turn:
    """
    The agent receives its own previous output as the next user message.

    Simulates infinite reflection / runaway recursion.
    """
    reflected_msg = {
        "role": "user",
        "content": [
            {
                "type": "text",
                "text": f"[REFLECTED]: {previous_output or 'Previous assistant output injected here.'}",
            }
        ],
    }
    chunk = StreamChunk(
        index=0,
        raw_hex=f"data: {orjson.dumps(reflected_msg).decode()}\n\n".encode().hex(),
        anomalous=True,
    )
    return turn.model_copy(
        update={
            "request_body": {
                **(turn.request_body or {}),
                "messages": [reflected_msg],
            },
            "stream_chunks": [chunk],
        }
    )


def _scenario_iam_constraint_hallucination(turn: Turn) -> Turn:
    """
    Tool result returns a fake AWS IAM permission denial.

    Forces the agent to attempt permission escalation or fallback.
    """
    iam_error = {
        "type": "tool_result",
        "tool_use_id": f"toolu_{uuid.uuid4().hex[:12]}",
        "content": (
            "Error: User: arn:aws:sts::123456789012:assumed-role/agent-role/session "
            "is not authorized to perform: iam:PassRole on resource: "
            "arn:aws:iam::*:role/* because no identity-based policy allows the "
            "iam:PassRole action"
        ),
        "is_error": True,
    }
    chunk = StreamChunk(
        index=0,
        raw_hex=f"data: {orjson.dumps(iam_error).decode()}\n\n".encode().hex(),
        anomalous=False,
    )
    return turn.model_copy(update={"stream_chunks": [chunk]})


def _scenario_infinite_context_growth(turn: Turn, extra_tokens: int = 50_000) -> Turn:
    """
    Inflate the context by injecting a massive synthetic history block.

    Tests whether the agent handles context window exhaustion gracefully.
    """
    filler = " ".join([f"token_{i}" for i in range(extra_tokens // 6)])
    inflated_body = {
        **(turn.request_body or {}),
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": filler}],
            },
            {
                "role": "assistant",
                "content": [{"type": "text", "text": filler}],
            },
        ],
    }
    return turn.model_copy(
        update={
            "request_body": inflated_body,
            "token_usage": {"input_tokens": extra_tokens, "output_tokens": 0},
        }
    )


_SCENARIO_MAP = {
    ScenarioType.HALLUCINATED_TOOL: _scenario_hallucinated_tool,
    ScenarioType.STREAM_MID_TRUNCATION: _scenario_stream_mid_truncation,
    ScenarioType.PROVIDER_MODEL_SWAP: _scenario_provider_model_swap,
    ScenarioType.REFLECTION_LOOP: _scenario_reflection_loop,
    ScenarioType.IAM_CONSTRAINT_HALLUCINATION: _scenario_iam_constraint_hallucination,
    ScenarioType.INFINITE_CONTEXT_GROWTH: _scenario_infinite_context_growth,
}


# ---------------------------------------------------------------------------
# Fabricator
# ---------------------------------------------------------------------------


class Fabricator:
    """
    Produces synthetic CamouflageSession instances.

    If a seed session is provided, it is mutated by the scenario transform.
    Otherwise, a minimal synthetic session is created from scratch.
    """

    def __init__(self, clock: HLCClock) -> None:
        self._clock = clock

    def fabricate(
        self,
        scenario: ScenarioType,
        client: AgentClient,
        seed: Session | None = None,
        inject_at_turn: int = -1,
        **scenario_kwargs: Any,
    ) -> CamouflageSession:
        """
        Generate a camouflage session.

        Args:
            scenario:         Which chaos scenario to apply.
            client:           Agent client to simulate.
            seed:             Optional real session to use as base.
            inject_at_turn:   Which turn index to inject the scenario (-1 = last).
            **scenario_kwargs: Extra args forwarded to the scenario function.
        """
        base_turns = self._turns_from_seed(seed) if seed else self._minimal_turns(client)
        transform = _SCENARIO_MAP.get(scenario)

        if transform and base_turns:
            idx = inject_at_turn if inject_at_turn >= 0 else len(base_turns) - 1
            idx = min(idx, len(base_turns) - 1)
            mutated = list(base_turns)
            mutated[idx] = transform(mutated[idx], **scenario_kwargs)
            base_turns = mutated

        return CamouflageSession(
            id=str(uuid.uuid4()),
            scenario=scenario,
            seed_session_id=seed.id if seed else None,
            client=client,
            injected_at=HLCModel.from_hlc(self._clock.tick()),
            turns=base_turns,
            metadata={"scenario_kwargs": scenario_kwargs},
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _turns_from_seed(self, seed: Session) -> list[Turn]:
        """Deep-copy turns from a real session."""
        return [t.model_copy(deep=True) for t in seed.turns]

    def _minimal_turns(self, client: AgentClient) -> list[Turn]:
        """Synthesise a minimal one-turn session skeleton."""
        body: dict[str, Any] = {
            "model": "claude-sonnet-4-6",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "Hello."}]}
            ],
        }
        chunk = StreamChunk(
            index=0,
            raw_hex=b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi."}}\n\n'.hex(),
            anomalous=False,
        )
        turn = Turn(
            index=0,
            request_headers={
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            },
            request_body=body,
            response_status=200,
            stream_chunks=[chunk],
            token_usage={"input_tokens": random.randint(100, 500), "output_tokens": random.randint(10, 100)},
            duration_ms=random.uniform(200, 1500),
        )
        return [turn]
