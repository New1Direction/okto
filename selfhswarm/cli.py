"""
selfhswarm CLI entrypoint.

Commands:
  selfhswarm run       -- start proxy for a supported agent client
  selfhswarm broker    -- run the RNA bus broker server
  selfhswarm fabricate -- generate a camouflage session
  selfhswarm genome    -- inspect / manage the local genome
  selfhswarm ca        -- manage the local TLS CA cert
"""

from __future__ import annotations

import asyncio
import logging
import os
import pathlib
import subprocess
import sys
import uuid
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from selfhswarm import __version__
from selfhswarm.models import AgentClient, ScenarioType

console = Console()
log = logging.getLogger("selfhswarm")


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


def _node_id_path() -> pathlib.Path:
    return pathlib.Path.home() / ".selfhswarm" / "node_id"


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
@click.version_option(__version__, prog_name="selfhswarm")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """selfhswarm — self-mutating swarm proxy for AI coding agents."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


# ---------------------------------------------------------------------------
# selfhswarm run
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
    default=str(pathlib.Path.home() / ".selfhswarm" / "sessions"),
    show_default=True,
    help="Directory for captured session JSONL files.",
)
@click.option("--no-live-viewer", is_flag=True, default=False, help="Disable live viewer server.")
@click.option("--viewer-port", default=7878, show_default=True, help="Port for the Traffic Inspector dashboard.")
@click.argument("agent_args", nargs=-1)
@click.pass_context
def run(
    ctx: click.Context,
    client: str,
    upstream: Optional[str],
    proxy_port: int,
    broker: Optional[str],
    session_dir: str,
    no_live_viewer: bool,
    viewer_port: int,
    agent_args: tuple,
) -> None:
    """
    Start the self-patching proxy and launch the agent CLI through it.

    Extra arguments after -- are forwarded to the agent CLI.

    Examples:

      selfhswarm run --client claude -- --model claude-opus-4-6

      selfhswarm run --client gemini -- -p "hello"

      selfhswarm run --client agy
    """
    node_id = _get_or_create_node_id()
    client_enum = AgentClient(client)

    console.rule(f"[bold cyan]selfhswarm v{__version__}[/bold cyan]")
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
    agent_args: list[str] = [],
) -> None:
    from selfhswarm.hlc import HLCClock
    from selfhswarm.rna_bus.ledger import GenomeLedger
    from selfhswarm.rna_bus.broker import RNAClient
    from selfhswarm.proxy.addon import SelfHSwarmProxy
    from selfhswarm.viewer.events import EventBus
    from selfhswarm.viewer.server import start_viewer

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
            f"[green]✓[/green] Dashboard live at [bold cyan]http://127.0.0.1:{viewer_port}[/bold cyan]"
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
    _MAP = {
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
    return _MAP.get(client, ["claude"])


# ---------------------------------------------------------------------------
# selfhswarm broker
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
# selfhswarm fabricate
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
@click.option("--output", "-o", default=None, help="Output path for the synthetic session JSONL.")
@click.pass_context
def fabricate(
    ctx: click.Context,
    scenario: str,
    client: str,
    seed_session: Optional[str],
    output: Optional[str],
) -> None:
    """Generate a synthetic camouflage session for chaos testing."""
    import orjson

    from selfhswarm.camouflage.fabricator import Fabricator
    from selfhswarm.hlc import HLCClock
    from selfhswarm.models import ScenarioType as ST, AgentClient as AC, Session

    node_id = _get_or_create_node_id()
    clock = HLCClock(node_id)
    fab = Fabricator(clock)

    seed: Session | None = None
    if seed_session:
        data = orjson.loads(pathlib.Path(seed_session).read_bytes())
        seed = Session.model_validate(data)

    result = fab.fabricate(
        scenario=ST(scenario),
        client=AC(client),
        seed=seed,
    )

    out_bytes = orjson.dumps(result.model_dump(), option=orjson.OPT_INDENT_2)
    if output:
        pathlib.Path(output).write_bytes(out_bytes)
        console.print(f"[green]✓[/green] Camouflage session written to {output}")
    else:
        console.print(out_bytes.decode())


# ---------------------------------------------------------------------------
# selfhswarm genome
# ---------------------------------------------------------------------------


@main.group()
def genome() -> None:
    """Inspect and manage the local mutation genome."""


@genome.command(name="list")
@click.option("--client", default=None, help="Filter by client.")
@click.option("--min-confidence", default=0.1, show_default=True)
def genome_list(client: Optional[str], min_confidence: float) -> None:
    """List all mutations in the local genome."""
    import asyncio
    import orjson
    from selfhswarm.rna_bus.ledger import GenomeLedger
    from selfhswarm.models import AgentClient as AC

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
    p = pathlib.Path.home() / ".selfhswarm" / "genome.jsonl"
    if p.exists():
        p.unlink()
    console.print("[green]✓[/green] Genome cleared.")


# ---------------------------------------------------------------------------
# selfhswarm ca
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
