"""
Layer 3 — RNA Bus: Append-only genome ledger.

The genome is stored as JSONL at ~/.okto/genome.jsonl.
Each line is one Mutation, stamped with an HLC.

The ledger is append-only: mutations are never deleted, only pruned
in memory when confidence drops below the threshold. The on-disk log
is the full history; in-memory Genome is the live working set.

Thread-safety: all writes go through asyncio; the file is opened in
append mode so concurrent processes on the same machine will not
corrupt it (writes are atomic for lines < PIPE_BUF on POSIX).
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
from collections.abc import Callable

import orjson

from selfhswarm.models import Genome, Mutation

log = logging.getLogger(__name__)

_DEFAULT_PATH = pathlib.Path.home() / ".okto" / "genome.jsonl"


class GenomeLedger:
    """
    Stateful genome ledger for one node.

    Usage::

        ledger = await GenomeLedger.load(node_id="abc123")
        ledger.append(mutation)           # add a new mutation
        mutations = ledger.genome.for_client(AgentClient.CLAUDE)
    """

    def __init__(
        self,
        node_id: str,
        genome: Genome,
        path: pathlib.Path,
        on_append: Callable[[Mutation], None] | None = None,
    ) -> None:
        self.node_id = node_id
        self.genome = genome
        self._path = path
        self._on_append = on_append or (lambda _: None)
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    async def load(
        cls,
        node_id: str,
        path: pathlib.Path = _DEFAULT_PATH,
        on_append: Callable[[Mutation], None] | None = None,
    ) -> GenomeLedger:
        """Load genome from JSONL ledger file, or start fresh."""
        path.parent.mkdir(parents=True, exist_ok=True)
        genome = Genome(node_id=node_id)

        if path.exists():
            mutations_loaded = 0
            for line in path.read_bytes().split(b"\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = orjson.loads(line)
                    mut = Mutation.model_validate(data)
                    genome = genome.apply(mut)
                    mutations_loaded += 1
                except Exception as exc:
                    log.warning("Skipping malformed genome line: %s", exc)
            log.info("Loaded genome: %d mutations from %s", mutations_loaded, path)

        # Prune stale mutations on load
        genome = genome.prune()
        return cls(node_id=node_id, genome=genome, path=path, on_append=on_append)

    # ------------------------------------------------------------------
    # Mutation management
    # ------------------------------------------------------------------

    def append(self, mutation: Mutation) -> None:
        """
        Append a mutation to the in-memory genome and schedule a disk write.

        This is synchronous (called from the state machine on the hot path)
        but the disk write is fire-and-forget via asyncio.
        """
        self.genome = self.genome.apply(mutation)
        self._on_append(mutation)
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(self._write_mutation(mutation))
        except RuntimeError:
            # No running loop (e.g. in tests) — write synchronously
            self._write_mutation_sync(mutation)

    def apply_remote(self, mutation: Mutation) -> None:
        """
        Apply a mutation received from a remote node (RNA bus).

        Same as append but does NOT trigger the on_append callback
        (which would re-broadcast it).
        """
        self.genome = self.genome.apply(mutation)
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(self._write_mutation(mutation))
        except RuntimeError:
            self._write_mutation_sync(mutation)

    async def merge_delta(self, mutations: list[Mutation]) -> int:
        """
        Merge a list of mutations received from the broker.

        Returns the number of new mutations applied.
        """
        applied = 0
        async with self._lock:
            existing_ids = {m.id for m in self.genome.mutations}
            for mut in sorted(mutations, key=lambda m: m.hlc):
                if mut.id not in existing_ids:
                    self.apply_remote(mut)
                    applied += 1
        return applied

    def decay_all(self, hours_elapsed: float) -> None:
        """Apply confidence decay across all mutations (call periodically)."""
        decayed = [m.decayed(hours_elapsed) for m in self.genome.mutations]
        self.genome = Genome(node_id=self.node_id, mutations=decayed).prune()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _write_mutation(self, mutation: Mutation) -> None:
        async with self._lock:
            await asyncio.get_event_loop().run_in_executor(
                None, self._write_mutation_sync, mutation
            )

    def _write_mutation_sync(self, mutation: Mutation) -> None:
        with self._path.open("ab") as f:
            f.write(orjson.dumps(mutation.model_dump()) + b"\n")
