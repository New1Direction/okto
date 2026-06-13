"""Tests for the genome ledger (append-only JSONL store)."""

import asyncio
import pathlib
import tempfile

import pytest

from selfhswarm.hlc import HLCClock
from selfhswarm.models import AgentClient, HLCModel, Mutation, MutationScope
from selfhswarm.rna_bus.ledger import GenomeLedger


def _make_mutation(clock: HLCClock, client=AgentClient.CLAUDE) -> Mutation:
    t = clock.tick()
    return Mutation(
        hlc=HLCModel.from_hlc(t),
        client=client,
        scope=MutationScope.STREAM_CHUNK,
        pattern_hex=b"bad".hex(),
        patch_hex=b"data: bad".hex(),
        confidence=1.0,
        source_node="test",
    )


@pytest.fixture
def tmp_path_ledger():
    with tempfile.TemporaryDirectory() as d:
        yield pathlib.Path(d) / "genome.jsonl"


class TestGenomeLedger:
    def test_load_empty(self, tmp_path_ledger):
        ledger = asyncio.run(GenomeLedger.load("n", tmp_path_ledger))
        assert len(ledger.genome.mutations) == 0

    def test_append_and_reload(self, tmp_path_ledger):
        clock = HLCClock("n")
        ledger = asyncio.run(GenomeLedger.load("n", tmp_path_ledger))
        mut = _make_mutation(clock)
        ledger.append(mut)

        # Force sync write (no event loop)
        ledger._write_mutation_sync(mut)

        # Reload from disk
        ledger2 = asyncio.run(GenomeLedger.load("n", tmp_path_ledger))
        ids = {m.id for m in ledger2.genome.mutations}
        assert mut.id in ids

    def test_confidence_decay(self, tmp_path_ledger):
        clock = HLCClock("n")
        ledger = asyncio.run(GenomeLedger.load("n", tmp_path_ledger))
        mut = _make_mutation(clock)
        ledger.append(mut)

        ledger.decay_all(hours_elapsed=100)
        remaining = [m for m in ledger.genome.mutations if m.id == mut.id]
        if remaining:
            assert remaining[0].confidence < 1.0
        # Might be pruned entirely if decay brought it below 0.1

    def test_duplicate_mutation_not_duplicated(self, tmp_path_ledger):
        clock = HLCClock("n")
        ledger = asyncio.run(GenomeLedger.load("n", tmp_path_ledger))
        mut = _make_mutation(clock)
        ledger.append(mut)
        ledger.append(mut)  # same mutation twice
        ids = [m.id for m in ledger.genome.mutations]
        assert ids.count(mut.id) == 1

    def test_merge_delta_applies_new_mutations(self, tmp_path_ledger):
        clock = HLCClock("n")
        ledger = asyncio.run(GenomeLedger.load("n", tmp_path_ledger))
        remote_muts = [_make_mutation(clock) for _ in range(3)]
        applied = asyncio.run(ledger.merge_delta(remote_muts))
        assert applied == 3
        assert len(ledger.genome.mutations) == 3

    def test_merge_delta_skips_known_mutations(self, tmp_path_ledger):
        clock = HLCClock("n")
        ledger = asyncio.run(GenomeLedger.load("n", tmp_path_ledger))
        mut = _make_mutation(clock)
        ledger.append(mut)
        applied = asyncio.run(ledger.merge_delta([mut]))
        assert applied == 0  # already known

    def test_on_append_callback_fired(self, tmp_path_ledger):
        clock = HLCClock("n")
        received = []
        ledger = asyncio.run(
            GenomeLedger.load("n", tmp_path_ledger, on_append=received.append)
        )
        mut = _make_mutation(clock)
        ledger.append(mut)
        assert len(received) == 1
        assert received[0].id == mut.id
