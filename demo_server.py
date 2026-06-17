"""Standalone demo server for screenshots; injects synthetic events then runs forever."""

from __future__ import annotations

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from selfhswarm.models import LiveEvent, LiveEventType
from selfhswarm.viewer.events import EventBus
from selfhswarm.viewer.server import start_viewer


async def main() -> None:
    bus = EventBus()
    session_dir = pathlib.Path("/tmp/selfhswarm-demo3")
    session_dir.mkdir(exist_ok=True)

    await start_viewer(bus, str(session_dir), "demo-node", None, "127.0.0.1", 7878)
    await asyncio.sleep(1.5)

    sid = "abc12345-0000-0000-0000-000000000042"
    await bus.publish(
        LiveEvent(
            type=LiveEventType.SESSION_START,
            session_id=sid,
            payload={
                "connect_target": "api.anthropic.com:443",
                "tls_established": True,
                "provider": {
                    "vendor": "Anthropic",
                    "product": "Claude",
                    "hostname": "api.anthropic.com",
                },
                "client": "claude",
            },
        )
    )
    await asyncio.sleep(0.3)

    raw_hex = bytes('{"choices":[{"delta":{"content":"hello"}}]}', "utf-8").hex()
    exp_hex = bytes('data: {"choices":[{"delta":{"content":"hello"}}]}', "utf-8").hex()
    await bus.publish(
        LiveEvent(
            type=LiveEventType.ANOMALY_DETECTED,
            session_id=sid,
            payload={
                "turn_index": 0,
                "chunk_index": 4,
                "anomaly_type": "bare_json_without_data_prefix",
                "raw_hex": raw_hex,
                "expected_hex": exp_hex,
            },
        )
    )
    await asyncio.sleep(0.3)

    await bus.publish(
        LiveEvent(
            type=LiveEventType.MUTATION_DERIVED,
            session_id=sid,
            payload={
                "mutation": {
                    "id": "a3f2c1d8-dead-beef-cafe-000000000000",
                    "scope": "stream_chunk",
                    "client": "claude",
                    "pattern_hex": bytes('{"', "utf-8").hex(),
                    "patch_hex": bytes('data: {"', "utf-8").hex(),
                    "confidence": 1.0,
                    "reinforcement_count": 0,
                }
            },
        )
    )

    print("READY http://127.0.0.1:7878", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
