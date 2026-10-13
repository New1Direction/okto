"""
Session replay: run captured chunks back through a fresh state machine.

Shared by the Traffic Inspector (``POST /api/sessions/{id}/replay``) and the
Korg exporter, so both report the same evidence for the same session.
"""

from __future__ import annotations

from selfhswarm.hlc import HLCClock
from selfhswarm.models import (
    ChunkReplay,
    Mutation,
    MutationScope,
    ReplayResult,
    Session,
    TurnReplay,
)
from selfhswarm.proxy.state_machine import ProxyStateMachine


def replay_session(session: Session, mutations: list[Mutation], node_id: str) -> ReplayResult:
    """
    Replay every turn of *session* against *mutations* (usually the current
    genome for the session's client). Nothing is persisted: mutations derived
    during replay stay local to the run.
    """
    replay_node = f"replay-{node_id[:8]}"
    clock = HLCClock(replay_node)
    turn_results: list[TurnReplay] = []
    total_anomalies = 0
    total_mutations = 0

    for turn in session.turns:
        sm = ProxyStateMachine(
            client=session.client,
            node_id=replay_node,
            session_id=session.id,
            genome_mutations=list(mutations),  # fresh copy per turn
            clock=clock,
        )
        chunk_replays: list[ChunkReplay] = []
        t_anomalies = 0
        t_mutations = 0

        for chunk in turn.stream_chunks:
            raw = bytes.fromhex(chunk.raw_hex)
            rewritten, meta = sm.process_chunk(raw, MutationScope.STREAM_CHUNK)

            resolved = meta.applied_mutation_id is not None
            chunk_replays.append(
                ChunkReplay(
                    index=meta.index,
                    raw_hex=chunk.raw_hex,
                    patched_hex=rewritten.hex() if resolved else None,
                    anomalous=meta.anomalous,
                    anomaly_type=meta.anomaly_type,
                    mutation_id=meta.applied_mutation_id,
                    resolved=resolved,
                )
            )
            if meta.anomalous:
                t_anomalies += 1
            if meta.applied_mutation_id:
                t_mutations += 1

        turn_results.append(
            TurnReplay(
                turn_index=turn.index,
                chunks=chunk_replays,
                anomalies_detected=t_anomalies,
                mutations_applied=t_mutations,
                resolved=(t_anomalies == t_mutations),
            )
        )
        total_anomalies += t_anomalies
        total_mutations += t_mutations

    return ReplayResult(
        session_id=session.id,
        turn_results=turn_results,
        total_anomalies=total_anomalies,
        total_mutations_applied=total_mutations,
        resolved=(total_anomalies == total_mutations),
    )
