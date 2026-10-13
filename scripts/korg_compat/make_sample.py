"""Write sample Okto→Korg exports (plain and HMAC-chained) for the compat check."""

from __future__ import annotations

import pathlib
import sys

import orjson

from selfhswarm.hlc import HLCClock
from selfhswarm.korg import Capture, Fingerprinter, export_capture, load_or_create_chain_key
from selfhswarm.models import (
    AgentClient,
    HLCModel,
    Mutation,
    MutationScope,
    Session,
    Turn,
    detect_provider,
)
from selfhswarm.proxy.state_machine import ProxyStateMachine

CHUNKS = [
    b'data: {"type":"content_block_delta","delta":{"text":"hello"}}\n\n',
    b'{"type":"content_block_delta","delta":{"text":"bare"}}',  # repairable
    b'data: {"type":"content_block_delta","delta":{"te',  # not repairable
    b"data: [DONE]\n\n",
]


def main(out: pathlib.Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    clock = HLCClock("compat-node")
    session = Session(
        client=AgentClient.CLAUDE,
        node_id="compat-node",
        started_at_hlc=HLCModel.from_hlc(clock.tick()),
        provider=detect_provider("api.anthropic.com"),
        tls_established=True,
    )
    derived: list[Mutation] = []
    sm = ProxyStateMachine(AgentClient.CLAUDE, "compat-node", session.id, [], clock,
                           on_new_mutation=derived.append)
    for index in range(3):
        turn = Turn(index=index, request_body={"model": "claude-opus-4-6", "stream": True},
                    token_usage={"input_tokens": 100, "output_tokens": 20}, duration_ms=250.0)
        for raw in CHUNKS:
            turn.stream_chunks.append(sm.process_chunk(raw, MutationScope.STREAM_CHUNK)[1])
        session.turns.append(turn)

    capture = Capture(session=session, source_bytes=orjson.dumps(session.model_dump()))
    fp = Fingerprinter.load_or_create(out / "fingerprint.key")
    chain_key = load_or_create_chain_key(out / "chain.key")
    (out / "plain.korg.jsonl").write_bytes(export_capture(capture, fp, derived))
    (out / "keyed.korg.jsonl").write_bytes(
        export_capture(capture, fp, derived, chain_key=chain_key)
    )


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]))
