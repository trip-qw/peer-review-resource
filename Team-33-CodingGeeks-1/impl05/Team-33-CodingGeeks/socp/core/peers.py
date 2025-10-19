from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import yaml

from . import presence as presence_mod
from .proto import make_envelope, now_ms, is_uuid_v4

log = logging.getLogger("socp.peers")

SendFn = Callable[[dict], None]
SignFn = Callable[[bytes], str]
NowFn = Callable[[], int]

CONFIG_PATH = Path("configs/bootstrap.yaml")


@dataclass
class Link:
    server_id: str
    host: str
    port: int
    pubkey_b64: str
    send: SendFn = lambda _msg: None
    last_seen_ms: int = field(default_factory=now_ms)
    is_alive: bool = True
    reconnecting: bool = False

    def touch(self, now: int) -> None:
        self.last_seen_ms = now
        self.is_alive = True
        self.reconnecting = False


class PeerManager:
    """Tracks overlay servers and their health."""

    def __init__(
        self,
        my_server_id: str,
        sign_transport: SignFn,
        now: NowFn = now_ms,
        on_dead: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.my_server_id = my_server_id
        self.sign_transport = sign_transport
        self.now = now
        self.on_dead = on_dead

        self.server_links: Dict[str, Link] = {}
        self.server_addrs: Dict[str, Tuple[str, int]] = {}
        self.user_locations: Dict[str, str] = {}
        self._placeholders: set[str] = set()
        self._pending_announce: Optional[dict] = None

    # ------------------------------------------------------------------
    # Envelope helpers
    # ------------------------------------------------------------------

    def make_server_hello_join(self, intro_host: str, intro_port: int, my_pubkey_b64: str) -> dict:
        to = f"{intro_host}:{intro_port}"
        payload = {"host": intro_host, "port": intro_port, "pubkey": my_pubkey_b64}
        return make_envelope("SERVER_HELLO_JOIN", self.my_server_id, to, payload, self.sign_transport)

    def make_server_announce(self, my_host: str, my_port: int, my_pubkey_b64: str) -> dict:
        payload = {"host": my_host, "port": my_port, "pubkey": my_pubkey_b64}
        return make_envelope("SERVER_ANNOUNCE", self.my_server_id, "*", payload, self.sign_transport)

    def make_heartbeat(self, to_server_id: str) -> dict:
        return make_envelope("HEARTBEAT", self.my_server_id, to_server_id, {}, self.sign_transport)

    # ------------------------------------------------------------------
    # Config / bootstrap utilities
    # ------------------------------------------------------------------

    def load_config(self, override_path: Optional[str] = None) -> List[dict]:
        path = Path(override_path) if override_path else CONFIG_PATH
        if not path.exists():
            return []
        data = yaml.safe_load(path.read_text()) or {}
        introducers = data.get("bootstrap_servers") or data.get("introducers") or []
        result = []
        for entry in introducers:
            if not entry:
                continue
            host = entry.get("host")
            port = entry.get("port")
            pubkey = entry.get("pubkey")
            if host and port is not None and pubkey:
                result.append({"host": host, "port": int(port), "pubkey": pubkey})
        return result

    # ------------------------------------------------------------------
    # Frame ingress
    # ------------------------------------------------------------------

    def on_server_frame(self, envelope: dict) -> None:
        frame_type = envelope.get("type")
        sender = envelope.get("from")
        link = self.server_links.get(sender)
        if link:
            link.touch(self.now())

        if frame_type == "SERVER_WELCOME":
            self._handle_server_welcome(envelope)
        elif frame_type == "SERVER_ANNOUNCE":
            self._handle_server_announce(envelope)
        elif frame_type == "USER_ADVERTISE":
            presence_mod.handle_user_advertise(
                envelope,
                my_server_id=self.my_server_id,
                user_locations=self.user_locations,
                verify_from_server=lambda _env: True,
                fanout=lambda _env: None,
            )
        elif frame_type == "USER_REMOVE":
            presence_mod.handle_user_remove(
                envelope,
                my_server_id=self.my_server_id,
                user_locations=self.user_locations,
                verify_from_server=lambda _env: True,
                fanout=lambda _env: None,
            )
        elif frame_type == "HEARTBEAT":
            if link:
                link.touch(self.now())

    def _handle_server_welcome(self, envelope: dict) -> None:
        introducer_id = envelope.get("from")
        payload = envelope.get("payload") or {}
        clients = payload.get("clients") or []

        self._promote_placeholder(introducer_id)

        for client in clients:
            uid = client.get("user_id")
            if not uid:
                continue
            hosting = client.get("server_id") or introducer_id
            self.user_locations[uid] = hosting

    def _handle_server_announce(self, envelope: dict) -> None:
        sender = envelope.get("from")
        payload = envelope.get("payload") or {}
        host = payload.get("host")
        port = payload.get("port")
        pubkey = payload.get("pubkey")
        if not sender or host is None or port is None or pubkey is None:
            return
        port = int(port)
        link = self.server_links.get(sender)
        if link is None:
            link = Link(server_id=sender, host=host, port=port, pubkey_b64=pubkey)
            self.server_links[sender] = link
        else:
            link.host = host
            link.port = port
            link.pubkey_b64 = pubkey
        link.touch(self.now())
        self.server_addrs[sender] = (host, port)

    def _promote_placeholder(self, real_id: str) -> None:
        if not real_id:
            return
        if real_id in self.server_links:
            return
        for placeholder in list(self._placeholders):
            link = self.server_links.pop(placeholder, None)
            if not link:
                self._placeholders.discard(placeholder)
                continue
            self._placeholders.discard(placeholder)
            link.server_id = real_id
            self.server_links[real_id] = link
            self.server_addrs[real_id] = (link.host, link.port)
            link.touch(self.now())
            break

    # ------------------------------------------------------------------
    # Health / maintenance
    # ------------------------------------------------------------------

    def tick_health(self, timeout_s: float = 45.0) -> None:
        deadline_ms = timeout_s * 1000
        now = self.now()
        for sid, link in list(self.server_links.items()):
            if now - link.last_seen_ms > deadline_ms:
                if link.is_alive:
                    link.is_alive = False
                    link.reconnecting = True
                    if self.on_dead:
                        try:
                            self.on_dead(sid)
                        except Exception:  # pragma: no cover - defensive
                            log.exception("on_dead callback failed for %s", sid)

    # ------------------------------------------------------------------
    # Placeholder utilities used during bootstrap
    # ------------------------------------------------------------------

    def register_placeholder(self, host: str, port: int, pubkey_b64: str, send: SendFn) -> Link:
        sid = f"{host}:{port}"
        link = Link(server_id=sid, host=host, port=port, pubkey_b64=pubkey_b64, send=send)
        self.server_links[sid] = link
        self.server_addrs[sid] = (host, port)
        self._placeholders.add(sid)
        return link


async def bootstrap(
    *,
    my_server_id: str,
    my_host: str,
    my_port: int,
    my_pubkey_b64: str,
    sign_transport: SignFn,
    bootstrap_list: Optional[List[dict]] = None,
    bootstrap_yaml_path: Optional[str] = None,
) -> PeerManager:
    """Utility used by higher layers to seed introducer placeholders.

    Real networking is out of scope for the tests; send() stubs simply log."""

    pm = PeerManager(my_server_id=my_server_id, sign_transport=sign_transport)

    introducers = bootstrap_list or pm.load_config(bootstrap_yaml_path)
    if not introducers:
        raise ValueError("No introducers available")

    for entry in introducers:
        host, port, pubkey = entry["host"], int(entry["port"]), entry["pubkey"]
        link = pm.register_placeholder(host, port, pubkey, _stub_send_factory(host, port))
        hello = pm.make_server_hello_join(host, port, my_pubkey_b64)
        link.send(hello)
        break

    pm._pending_announce = pm.make_server_announce(my_host, my_port, my_pubkey_b64)
    asyncio.create_task(_heartbeat_loop(pm))
    return pm


def _stub_send_factory(host: str, port: int) -> SendFn:
    def _send(msg: dict) -> None:
        log.debug("[stub-send %s:%s] %s", host, port, msg)
    return _send


async def _heartbeat_loop(pm: PeerManager, interval_s: float = 15.0) -> None:
    while True:
        try:
            pm.tick_health(timeout_s=45.0)
            for sid, link in list(pm.server_links.items()):
                if link.is_alive and is_uuid_v4(sid):
                    hb = pm.make_heartbeat(sid)
                    link.send(hb)
        except Exception:  # pragma: no cover - defensive
            log.exception("heartbeat loop error")
        await asyncio.sleep(interval_s)


__all__ = ["PeerManager", "Link", "bootstrap"]
