from __future__ import annotations

import argparse
import asyncio
import logging
import signal
from pathlib import Path

import yaml

from socp.server.runtime import ServerRuntime

log = logging.getLogger("socp.cmd.server")


async def _run(config_path: Path) -> None:
    config = yaml.safe_load(config_path.read_text()) or {}
    runtime = ServerRuntime(config)
    await runtime.start()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)
    except NotImplementedError:
        pass

    log.info("Server running. Press Ctrl+C to stop.")
    try:
        await stop_event.wait()
    finally:
        await runtime.stop()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="SOCP v1.3 compatible server")
    parser.add_argument("--config", required=True, help="Path to server YAML config")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    config_path = Path(args.config)
    asyncio.run(_run(config_path))


if __name__ == "__main__":
    main()
