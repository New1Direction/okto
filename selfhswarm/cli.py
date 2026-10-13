"""
Okto CLI entrypoint.

Commands:
  okto run       -- start proxy for a supported agent client
  okto broker    -- run the RNA bus broker server
  okto fabricate -- generate a camouflage session
  okto genome    -- inspect / manage the local genome
  okto ca        -- manage the local TLS CA cert
  okto korg      -- export sanitized diagnostics to a Korg ledger
"""

from __future__ import annotations

import asyncio
import logging
import os
import pathlib
import subprocess
import sys
import uuid

import click
from rich.console import Console
from rich.table import Table

from selfhswarm import __version__
from selfhswarm.models import AgentClient, ScenarioType

console = Console()
log = logging.getLogger("okto")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _app_dir() -> pathlib.Path:
    return pathlib.Path.home() / ".okto"


def _node_id_path() -> pathlib.Path:
    return _app_dir() / "node_id"


def _get_or_create_node_id() -> str:
    p = _node_id_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        return p.read_text().strip()
    nid = str(uuid.uuid4())
    p.write_text(nid)
    return nid


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(__version__, prog_name="okto")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """Okto — self-healing local proxy for AI agent traffic."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


# ---------------------------------------------------------------------------
# okto run
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--client",
    "-c",
    type=click.Choice([c.value for c in AgentClient if c != AgentClient.UNKNOWN]),
    default=AgentClient.CLAUDE.value,
    show_default=True,
    help="Agent client to proxy.",
)
@click.option("--upstream", "-u", default=None, help="Override upstream URL.")
@click.option("--proxy-port", default=8877, show_default=True, help="Local proxy port.")
@click.option(
    "--broker",
    default=None,
    help="RNA bus broker URL (e.g. ws://localhost:9373). Omit to run standalone.",
)
@click.option(
    "--session-dir",
    default=str(_app_dir() / "sessions"),
    show_default=True,
    help="Directory for captured session JSONL files.",
)
@click.option("--no-live-viewer", is_flag=True, default=False, help="Disable live viewer server.")
@click.option(
    "--viewer-port",
    default=7878,
    show_default=True,
    help="Port for the Traffic Inspector dashboard.",
)
@click.argument("agent_args", nargs=-1)
@click.pass_context
def run(
    ctx: click.Context,
    client: str,
    upstream: str | None,
    proxy_port: int,
    broker: str | None,
    session_dir: str,
    no_live_viewer: bool,
    viewer_port: int,
    agent_args: tuple,
) -> None:
    """
    Start the self-patching proxy and launch the agent CLI through it.

    Extra arguments after -- are forwarded to the agent CLI.

    Examples:

      okto run --client claude -- --model claude-opus-4-6

      okto run --client gemini -- -p "hello"

      okto run --client agy
    """
    node_id = _get_or_create_node_id()
    client_enum = AgentClient(client)

    console.rule(f"[bold cyan]Okto v{__version__}[/bold cyan]")
    console.print(f"  Node ID  : [dim]{node_id}[/dim]")
    console.print(f"  Client   : [bold]{client}[/bold]")
    console.print(f"  Upstream : [dim]{upstream or 'auto-detect'}[/dim]")
    console.print(f"  Proxy    : [bold]http://127.0.0.1:{proxy_port}[/bold]")
    console.print(f"  RNA bus  : [dim]{broker or 'standalone (no broker)'}[/dim]")
    if not no_live_viewer:
        console.print(f"  Dashboard: [bold cyan]http://127.0.0.1:{viewer_port}[/bold cyan]")
    console.print()

    asyncio.run(
        _run_proxy(
            node_id=node_id,
            client=client_enum,
            upstream=upstream,
            proxy_port=proxy_port,
            broker_url=broker,
            session_dir=session_dir,
            live_viewer=not no_live_viewer,
            viewer_port=viewer_port,
            agent_args=list(agent_args),
        )
    )


async def _run_proxy(
    node_id: str,
    client: AgentClient,
    upstream: str | None,
    proxy_port: int,
    broker_url: str | None,
    session_dir: str,
    live_viewer: bool,
    viewer_port: int = 7878,
    agent_args: list[str] | None = None,
) -> None:
    from selfhswarm.hlc import HLCClock
    from selfhswarm.proxy.addon import SelfHSwarmProxy
    from selfhswarm.rna_bus.broker import RNAClient
    from selfhswarm.rna_bus.ledger import GenomeLedger
    from selfhswarm.viewer.events import EventBus
    from selfhswarm.viewer.server import start_viewer

    agent_args = agent_args or []
    clock = HLCClock(node_id)
    session_path = pathlib.Path(session_dir)
    session_path.mkdir(parents=True, exist_ok=True)

    # Load (or create) local genome
    ledger = await GenomeLedger.load(node_id=node_id)
    console.print(
        f"[green]✓[/green] Genome loaded: {len(ledger.genome.mutations)} mutations"
    )

    # EventBus for live dashboard
    event_bus: EventBus | None = None
    viewer_task = None
    if live_viewer:
        event_bus = EventBus()
        viewer_task = await start_viewer(
            event_bus=event_bus,
            session_dir=session_dir,
            node_id=node_id,
            ledger=ledger,
            host="127.0.0.1",
            port=viewer_port,
        )
        # Give the server a moment to bind
        await asyncio.sleep(0.4)
        console.print(
            "[green]✓[/green] Dashboard live at "
            f"[bold cyan]http://127.0.0.1:{viewer_port}[/bold cyan]"
        )
        # Open browser
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:{viewer_port}")

    # Optional RNA bus connection
    rna_client: RNAClient | None = None
    if broker_url:
        rna_client = RNAClient(
            node_id=node_id,
            broker_url=broker_url,
            ledger=ledger,
            clock=clock,
        )
        # Wire new mutations to push to broker
        original_on_append = ledger._on_append

        async def _push_and_forward(mut):
            original_on_append(mut)
            await rna_client.push(mut)

        ledger._on_append = lambda m: asyncio.create_task(_push_and_forward(m))
        await rna_client.connect()
        console.print(f"[green]✓[/green] Connected to RNA broker at {broker_url}")

    # Start proxy
    proxy = SelfHSwarmProxy(
        client=client,
        upstream=upstream,
        ledger=ledger,
        clock=clock,
        session_dir=session_dir,
        event_bus=event_bus,
    )
    await proxy.start(port=proxy_port)
    console.print(f"[green]✓[/green] Proxy active on port {proxy_port}")

    # Set proxy env vars for the child process
    env = os.environ.copy()
    env["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
    env["HTTPS_PROXY"] = f"http://127.0.0.1:{proxy_port}"
    # Trust our self-signed CA
    from selfhswarm.proxy.tls import CertAuthority
    ca = CertAuthority()
    env["SSL_CERT_FILE"] = str(ca.ca_cert_path)
    env["REQUESTS_CA_BUNDLE"] = str(ca.ca_cert_path)

    if agent_args:
        # Launch agent CLI as subprocess through the proxy
        cmd = _resolve_client_cmd(client) + list(agent_args)
        console.print(f"[dim]Launching:[/dim] {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(*cmd, env=env)
        await proc.wait()
    else:
        # No agent args — just run the proxy and wait
        console.print("[dim]Proxy running. Press Ctrl+C to stop.[/dim]")
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            pass

    # Clean up viewer task
    if viewer_task and not viewer_task.done():
        viewer_task.cancel()
        try:
            await viewer_task
        except asyncio.CancelledError:
            pass


def _resolve_client_cmd(client: AgentClient) -> list[str]:
    client_commands = {
        AgentClient.CLAUDE: ["claude"],
        AgentClient.GEMINI: ["gemini"],
        AgentClient.CODEX: ["codex"],
        AgentClient.AGY: ["agy"],
        AgentClient.KIMI: ["kimi"],
        AgentClient.KIMI_CODE: ["kimi-code"],
        AgentClient.CURSOR: ["cursor"],
        AgentClient.OPENCODE: ["opencode"],
        AgentClient.PI: ["pi"],
        AgentClient.HERMES: ["hermes"],
    }
    return client_commands.get(client, ["claude"])


# ---------------------------------------------------------------------------
# okto broker
# ---------------------------------------------------------------------------


@main.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=9373, show_default=True)
@click.pass_context
def broker(ctx: click.Context, host: str, port: int) -> None:
    """Run the RNA bus broker server."""
    from selfhswarm.rna_bus.broker import RNABroker

    console.print(f"[bold cyan]RNA broker[/bold cyan] listening on ws://{host}:{port}")
    b = RNABroker()
    asyncio.run(b.serve(host=host, port=port))


# ---------------------------------------------------------------------------
# okto fabricate
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--scenario",
    "-s",
    type=click.Choice([s.value for s in ScenarioType if s != ScenarioType.CUSTOM]),
    required=True,
    help="Chaos scenario to inject.",
)
@click.option(
    "--client",
    "-c",
    type=click.Choice([c.value for c in AgentClient if c != AgentClient.UNKNOWN]),
    default=AgentClient.CLAUDE.value,
    show_default=True,
)
@click.option("--seed-session", default=None, help="Path to a real session JSONL to use as seed.")
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output path for the synthetic session JSONL.",
)
@click.pass_context
def fabricate(
    ctx: click.Context,
    scenario: str,
    client: str,
    seed_session: str | None,
    output: str | None,
) -> None:
    """Generate a synthetic camouflage session for chaos testing."""
    import orjson

    from selfhswarm.camouflage.fabricator import Fabricator
    from selfhswarm.hlc import HLCClock
    from selfhswarm.models import AgentClient, ScenarioType, Session

    node_id = _get_or_create_node_id()
    clock = HLCClock(node_id)
    fab = Fabricator(clock)

    seed: Session | None = None
    if seed_session:
        data = orjson.loads(pathlib.Path(seed_session).read_bytes())
        seed = Session.model_validate(data)

    result = fab.fabricate(
        scenario=ScenarioType(scenario),
        client=AgentClient(client),
        seed=seed,
    )

    out_bytes = orjson.dumps(result.model_dump(), option=orjson.OPT_INDENT_2)
    if output:
        pathlib.Path(output).write_bytes(out_bytes)
        console.print(f"[green]✓[/green] Camouflage session written to {output}")
    else:
        console.print(out_bytes.decode())


# ---------------------------------------------------------------------------
# okto genome
# ---------------------------------------------------------------------------


@main.group()
def genome() -> None:
    """Inspect and manage the local mutation genome."""


@genome.command(name="list")
@click.option("--client", default=None, help="Filter by client.")
@click.option("--min-confidence", default=0.1, show_default=True)
def genome_list(client: str | None, min_confidence: float) -> None:
    """List all mutations in the local genome."""
    import asyncio

    from selfhswarm.rna_bus.ledger import GenomeLedger

    node_id = _get_or_create_node_id()

    async def _load():
        return await GenomeLedger.load(node_id)

    ledger = asyncio.run(_load())
    mutations = ledger.genome.mutations

    if client:
        mutations = [m for m in mutations if m.client.value == client]
    mutations = [m for m in mutations if m.confidence >= min_confidence]
    mutations = sorted(mutations, key=lambda m: m.hlc, reverse=True)

    table = Table(title=f"Genome ({len(mutations)} mutations)")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Client")
    table.add_column("Scope")
    table.add_column("Confidence")
    table.add_column("Reinforcements")
    table.add_column("Description")

    for m in mutations:
        table.add_row(
            m.id[:8],
            m.client.value,
            m.scope.value,
            f"{m.confidence:.2f}",
            str(m.reinforcement_count),
            m.description[:60],
        )
    console.print(table)


@genome.command(name="clear")
@click.confirmation_option(prompt="Clear the entire local genome?")
def genome_clear() -> None:
    """Delete all mutations from the local genome."""
    p = _app_dir() / "genome.jsonl"
    if p.exists():
        p.unlink()
    console.print("[green]✓[/green] Genome cleared.")


# ---------------------------------------------------------------------------
# okto korg
# ---------------------------------------------------------------------------

_SESSION_ID_RE = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"


@main.group()
def korg() -> None:
    """Export sanitized diagnostics to a Korg ledger (korg-ledger@v1)."""


def _resolve_capture(session: str, session_dir: str) -> pathlib.Path:
    import re

    candidate = pathlib.Path(session)
    if candidate.is_file():
        return candidate
    if not re.fullmatch(_SESSION_ID_RE, session) or ".." in session:
        raise click.BadParameter("not a capture file or a session id", param_hint="SESSION")
    path = pathlib.Path(session_dir) / f"{session}.jsonl"
    if not path.is_file():
        raise click.BadParameter(f"no capture {session!r} in {session_dir}", param_hint="SESSION")
    return path


@korg.command(name="export")
@click.argument("sessions", nargs=-1)
@click.option(
    "--session-dir",
    default=str(_app_dir() / "sessions"),
    show_default=True,
    help="Where session ids (and --all) are looked up.",
)
@click.option("--all", "export_all", is_flag=True, default=False,
              help="Export every capture in --session-dir.")
@click.option(
    "--output", "-o", default=None,
    help="Write one export here (mode 0600). Default: stdout.",
)
@click.option(
    "--output-dir", default=None,
    help="Directory for batch exports, one <session-ref>.korg.jsonl per capture.",
)
@click.option(
    "--genome",
    "genome_path",
    default=str(_app_dir() / "genome.jsonl"),
    show_default=True,
    help="Genome used for repair summaries and replay evidence.",
)
@click.option("--no-replay", is_flag=True, default=False, help="Skip replay evidence.")
@click.option(
    "--key-file",
    default=str(_app_dir() / "korg_export.key"),
    show_default=True,
    help="Local HMAC key for fingerprints (created on first use; never exported).",
)
@click.option(
    "--chain-key-file", default=None,
    help="HMAC-key the hash chain (Korg tamper-proof mode). Created if missing.",
)
def korg_export(
    sessions: tuple[str, ...],
    session_dir: str,
    export_all: bool,
    output: str | None,
    output_dir: str | None,
    genome_path: str,
    no_replay: bool,
    key_file: str,
    chain_key_file: str | None,
) -> None:
    """
    Export captures as sanitized korg-ledger@v1 JSONL journals.

    SESSIONS are session ids from --session-dir or paths to capture files
    (proxy sessions or `okto fabricate` output). Headers, bodies, stream bytes,
    and mutation patterns stay local; each export carries labels, counts,
    keyed fingerprints, replay evidence, provenance, and causal links.
    Nothing is written for a capture that fails a boundary check.
    """
    import time

    from selfhswarm.korg import (
        BoundaryViolationError,
        Fingerprinter,
        export_capture,
        load_capture,
        load_or_create_chain_key,
        write_atomic,
    )
    from selfhswarm.rna_bus.ledger import GenomeLedger

    paths = [_resolve_capture(s, session_dir) for s in sessions]
    if export_all:
        paths += sorted(pathlib.Path(session_dir).glob("*.jsonl"))
    paths = list(dict.fromkeys(p.resolve() for p in paths))
    if not paths:
        raise click.UsageError("give at least one SESSION, or --all")
    batch = export_all or len(paths) > 1
    if batch and not output_dir:
        raise click.UsageError("exporting several captures needs --output-dir")
    if batch and output:
        raise click.UsageError("use --output-dir, not --output, for several captures")

    genome_file = pathlib.Path(genome_path)
    mutations = []
    if genome_file.is_file():
        ledger = asyncio.run(GenomeLedger.load("korg-export", path=genome_file))
        mutations = ledger.genome.mutations
    fingerprinter = Fingerprinter.load_or_create(pathlib.Path(key_file))
    chain_key = (
        load_or_create_chain_key(pathlib.Path(chain_key_file)) if chain_key_file else None
    )
    err = Console(stderr=True)

    failures = 0
    for path in paths:
        try:
            capture = load_capture(path)
            data = export_capture(
                capture,
                fingerprinter,
                mutations,
                replay=not no_replay,
                exported_at_ms=int(time.time() * 1000),
                chain_key=chain_key,
            )
        except BoundaryViolationError as exc:
            failures += 1
            err.print(f"[red]✗[/red] {path.name}: blocked at the Korg boundary: {exc}",
                      markup=True, highlight=False)
            continue
        except Exception as exc:
            failures += 1
            err.print(f"[red]✗[/red] {path.name}: cannot read capture ({type(exc).__name__})")
            continue

        count = data.count(b"\n")
        if batch:
            ref = fingerprinter(f"okto-session:{capture.session.id}").split(":", 1)[1][:16]
            target = pathlib.Path(output_dir) / f"{ref}.korg.jsonl"
            write_atomic(data, target)
            err.print(f"[green]✓[/green] {path.name} → {target} ({count} events)")
        elif output:
            write_atomic(data, pathlib.Path(output))
            err.print(f"[green]✓[/green] {count} events → {output}")
        else:
            click.echo(data.decode("ascii"), nl=False)

    if failures:
        raise click.ClickException(f"{failures} of {len(paths)} export(s) failed; nothing "
                                   "was written for them")


@korg.command(name="verify")
@click.argument("paths", nargs=-1, required=True,
                type=click.Path(exists=True, dir_okay=False))
@click.option("--chain-key-file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Chain key for exports made with --chain-key-file.")
def korg_verify(paths: tuple[str, ...], chain_key_file: str | None) -> None:
    """Check exports: hash chain, causal DAG, schema allowlist, secret scan."""
    from selfhswarm.korg import verify_export

    key = (
        pathlib.Path(chain_key_file).read_text().strip().encode("utf-8")
        if chain_key_file else None
    )
    bad = 0
    for path in paths:
        errors = verify_export(pathlib.Path(path).read_bytes(), key)
        if errors:
            bad += 1
            console.print(f"[red]✗[/red] {path}: {len(errors)} problem(s)", highlight=False)
            for e in errors[:50]:
                console.print(f"  - {e}", markup=False, highlight=False)
        else:
            console.print(
                f"[green]✓[/green] {path}: valid okto-korg-export@1 / korg-ledger@v1",
                highlight=False,
            )
    if bad:
        sys.exit(1)


# ---------------------------------------------------------------------------
# okto ca
# ---------------------------------------------------------------------------


@main.group()
def ca() -> None:
    """Manage the local TLS certificate authority."""


@ca.command(name="show")
def ca_show() -> None:
    """Print the path to the local CA cert."""
    from selfhswarm.proxy.tls import CertAuthority

    authority = CertAuthority()
    console.print(f"CA cert: [bold]{authority.ca_cert_path}[/bold]")


@ca.command(name="trust")
def ca_trust() -> None:
    """Add the local CA to the system trust store (macOS)."""
    from selfhswarm.proxy.tls import CertAuthority

    authority = CertAuthority()
    cert_path = str(authority.ca_cert_path)
    cmd = [
        "security", "add-trusted-cert", "-d", "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain", cert_path,
    ]
    console.print(f"Running: [dim]{' '.join(cmd)}[/dim]")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        console.print("[green]✓[/green] CA cert trusted.")
    else:
        console.print(f"[red]✗[/red] {result.stderr}")
        sys.exit(1)


if __name__ == "__main__":
    main()
