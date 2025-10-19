from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import websockets
from websockets.server import WebSocketServerProtocol

from socp.core import crypto, peers, proto, router, store

log = logging.getLogger("socp.server.runtime")


@dataclass(slots=True)
class Connection:
    websocket: WebSocketServerProtocol
    kind: str = "unknown"
    peer_id: Optional[str] = None
    peer_pubkey: Optional[bytes] = None
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send(self, frame: Dict[str, Any]) -> None:
        text = json.dumps(frame, separators=(",", ":"))
        async with self.send_lock:
            await self.websocket.send(text)


@dataclass(slots=True)
class UserSession:
    connection: Connection
    user_id: str
    sign_pub: bytes
    enc_pub: bytes
    sign_pub_b64: str
    enc_pub_b64: str
    meta: Dict[str, Any]


class ServerRuntime:
    """Minimal SOCP server runtime supporting local clients."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.cfg = config
        self.server_id = config["server_id"]
        self.listen_host, self.listen_port = self._parse_listen(config.get("listen", "0.0.0.0:7001"))
        self.db_path = config.get("db_path", "socp.db")
        self.key_dir = Path(config.get("key_dir", "keys/server"))
        self.bootstrap_file = config.get("bootstrap_file", "configs/bootstrap.yaml")
        self.heartbeat_secs = int(config.get("heartbeat_secs", 15))
        self.dead_after_secs = int(config.get("dead_after_secs", 45))
        vulns = config.get("vulns", {})
        self.vuln_weak_keys = bool(vulns.get("weak_keys", False))
        self.vuln_replay = bool(vulns.get("replay_bypass", False))

        self.private_key_pem, self.public_key_pem = (b"", b"")
        self._connections: list[Connection] = []
        self._user_sessions: Dict[str, UserSession] = {}
        self.user_locations: Dict[str, str] = {}

        self.public_channel_key = secrets.token_bytes(32)
        self.public_wraps: Dict[str, str] = {}
        self.public_version = 1

        self._ws_server: Optional[websockets.server.Serve] = None
        self._tasks: list[asyncio.Task] = []

        self.peer_manager: Optional[peers.PeerManager] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._configure_backdoors()
        self.private_key_pem, self.public_key_pem = self._ensure_server_keys()
        self._sign_transport = lambda payload: crypto.b64url(
            crypto.sign_pss_sha256(self.private_key_pem, payload)
        )

        await store.init(self.db_path)
        await store.ensure_public_group()

        self.peer_manager = peers.PeerManager(
            my_server_id=self.server_id,
            sign_transport=self._sign_transport,
        )

        self._ws_server = await websockets.serve(self._handle_connection, self.listen_host, self.listen_port)
        log.info("SOCP server %s listening on ws://%s:%d", self.server_id, self.listen_host, self.listen_port)

        self._tasks.append(asyncio.create_task(self._heartbeat_loop(), name="heartbeat"))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        for conn in list(self._connections):
            try:
                await conn.websocket.close()
            except Exception:
                pass
        self._connections.clear()

        if self._ws_server is not None:
            self._ws_server.close()
            await self._ws_server.wait_closed()
            self._ws_server = None

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    async def _handle_connection(self, websocket: WebSocketServerProtocol) -> None:
        conn = Connection(websocket=websocket)
        self._connections.append(conn)
        remote = self._fmt_remote(websocket)
        log.debug("Accepted connection from %s", remote)
        try:
            async for raw in websocket:
                try:
                    env = proto.Envelope(**json.loads(raw))
                except Exception:
                    await self._send_error(conn, "UNKNOWN_TYPE", "invalid envelope")
                    continue
                await self._dispatch(conn, env)
        except websockets.ConnectionClosed:
            pass
        finally:
            await self._on_disconnect(conn)
            try:
                self._connections.remove(conn)
            except ValueError:
                pass

    async def _dispatch(self, conn: Connection, envelope: proto.Envelope) -> None:
        type_ = envelope.type
        if type_ == "USER_HELLO":
            await self._handle_user_hello(conn, envelope)
        elif type_ == "LIST_USERS":
            await self._handle_list_users(conn)
        elif type_ == "MSG_DIRECT":
            await self._handle_msg_direct(conn, envelope)
        elif type_ == "MSG_PUBLIC_CHANNEL":
            await self._handle_public_message(conn, envelope)
        elif type_ in {"FILE_START", "FILE_CHUNK", "FILE_END"}:
            await self._handle_file_frame(conn, envelope)
        elif type_ == "HEARTBEAT":
            pass  # users do not need special handling
        else:
            await self._send_error(conn, "UNKNOWN_TYPE", f"unsupported type {type_}")

    # ------------------------------------------------------------------
    # User lifecycle
    # ------------------------------------------------------------------

    async def _handle_user_hello(self, conn: Connection, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        user_id = payload.get("client")
        pubkey_b64 = payload.get("pubkey")
        enc_pubkey_b64 = payload.get("enc_pubkey")
        meta = payload.get("meta", {})
        if not user_id or not pubkey_b64 or not enc_pubkey_b64:
            await self._send_error(conn, "UNKNOWN_TYPE", "invalid USER_HELLO payload")
            return
        if user_id in self._user_sessions:
            await self._send_error(conn, "NAME_IN_USE", "user already connected")
            return
        try:
            sign_pub = crypto.b64url_decode(pubkey_b64)
            enc_pub = crypto.b64url_decode(enc_pubkey_b64)
        except Exception:
            await self._send_error(conn, "BAD_KEY", "invalid key encoding")
            return
        if not crypto.accept_pubkey(sign_pub) or not crypto.accept_pubkey(enc_pub):
            await self._send_error(conn, "BAD_KEY", "RSA key rejected")
            return

        conn.kind = "user"
        conn.peer_id = user_id
        conn.peer_pubkey = sign_pub

        session = UserSession(
            connection=conn,
            user_id=user_id,
            sign_pub=sign_pub,
            enc_pub=enc_pub,
            sign_pub_b64=pubkey_b64,
            enc_pub_b64=enc_pubkey_b64,
            meta=meta,
        )
        self._user_sessions[user_id] = session
        self.user_locations[user_id] = "local"

        await self._send_envelope(conn, "ACK", user_id, {"msg_ref": "USER_HELLO"}, sign=False)
        await self._send_public_state(session)

    async def _handle_list_users(self, conn: Connection) -> None:
        if conn.kind != "user" or not conn.peer_id:
            await self._send_error(conn, "UNKNOWN_TYPE", "LIST_USERS only for users")
            return
        entries = []
        for uid, session in sorted(self._user_sessions.items()):
            entries.append(
                {
                    "user_id": uid,
                    "location": "local",
                    "meta": session.meta,
                    "pubkey": session.sign_pub_b64,
                    "enc_pubkey": session.enc_pub_b64,
                }
            )
        await self._send_envelope(conn, "LIST_USERS_RESULT", conn.peer_id, {"users": entries}, sign=False)

    async def _handle_msg_direct(self, conn: Connection, envelope: proto.Envelope) -> None:
        if conn.kind != "user" or conn.peer_id != envelope.from_:
            await self._send_error(conn, "UNKNOWN_TYPE", "MSG_DIRECT rejected")
            return
        payload = envelope.payload
        target = payload.get("to")
        ciphertext_b64 = payload.get("ciphertext")
        sender_pub_b64 = payload.get("sender_pub")
        content_sig = payload.get("content_sig")
        ts = payload.get("ts") or envelope.ts
        if not (target and ciphertext_b64 and sender_pub_b64 and content_sig and ts is not None):
            await self._send_error(conn, "UNKNOWN_TYPE", "malformed MSG_DIRECT payload")
            return
        try:
            ciphertext = crypto.b64url_decode(ciphertext_b64)
            sender_pub = crypto.b64url_decode(sender_pub_b64)
        except Exception:
            await self._send_error(conn, "BAD_KEY", "invalid base64 content")
            return
        digest = crypto.content_digest_direct(ciphertext, conn.peer_id, target, ts)
        if not crypto.verify_content_signature(sender_pub, digest, content_sig):
            await self._send_error(conn, "INVALID_SIG", "content signature invalid")
            return

        frame = envelope.model_dump(by_alias=True)
        action, detail = router.route_to_user(target, frame, self._user_sessions, self.user_locations)
        if action == "deliver_local":
            await self._deliver_dm_local(target, conn.peer_id, ciphertext_b64, sender_pub_b64, content_sig, ts)
            await self._send_envelope(conn, "ACK", conn.peer_id, {"msg_ref": f"MSG_DIRECT:{target}"}, sign=False)
        elif action == "forward":
            await self._send_error(conn, "USER_NOT_FOUND", "remote forwarding not implemented")
        else:
            await self._send_error(conn, "USER_NOT_FOUND", "unknown recipient")

    async def _handle_public_message(self, conn: Connection, envelope: proto.Envelope) -> None:
        if conn.kind != "user" or conn.peer_id != envelope.from_:
            await self._send_error(conn, "UNKNOWN_TYPE", "MSG_PUBLIC_CHANNEL rejected")
            return
        payload = envelope.payload
        ciphertext_b64 = payload.get("ciphertext")
        sender_pub_b64 = payload.get("sender_pub")
        content_sig = payload.get("content_sig")
        ts = payload.get("ts") or envelope.ts
        if not (ciphertext_b64 and sender_pub_b64 and content_sig and ts is not None):
            await self._send_error(conn, "UNKNOWN_TYPE", "malformed public payload")
            return
        try:
            ciphertext = crypto.b64url_decode(ciphertext_b64)
            sender_pub = crypto.b64url_decode(sender_pub_b64)
        except Exception:
            await self._send_error(conn, "BAD_KEY", "invalid base64 content")
            return
        digest = crypto.content_digest_public(ciphertext, conn.peer_id, ts)
        if not crypto.verify_content_signature(sender_pub, digest, content_sig):
            await self._send_error(conn, "INVALID_SIG", "content signature invalid")
            return
        await self._broadcast_public(conn.peer_id, ciphertext_b64, sender_pub_b64, content_sig, ts)

    async def _handle_file_frame(self, conn: Connection, envelope: proto.Envelope) -> None:
        if conn.kind != "user" or conn.peer_id != envelope.from_:
            await self._send_error(conn, "UNKNOWN_TYPE", "file frame rejected")
            return
        payload = dict(envelope.payload)
        target = payload.get("to") or payload.get("user_id")
        if not target:
            await self._send_error(conn, "UNKNOWN_TYPE", "file payload missing target")
            return
        frame = envelope.model_dump(by_alias=True)
        action, detail = router.route_to_user(target, frame, self._user_sessions, self.user_locations)
        if action != "deliver_local":
            await self._send_error(conn, "USER_NOT_FOUND", "file recipient unavailable")
            return
        await self._deliver_file_local(target, envelope.type, payload)

    async def _on_disconnect(self, conn: Connection) -> None:
        if conn.kind == "user" and conn.peer_id:
            user_id = conn.peer_id
            self._user_sessions.pop(user_id, None)
            self.public_wraps.pop(user_id, None)
            self.user_locations.pop(user_id, None)
            log.info("User %s disconnected", user_id)

    # ------------------------------------------------------------------
    # Deliveries
    # ------------------------------------------------------------------

    async def _deliver_dm_local(
        self,
        target: str,
        sender: str,
        ciphertext_b64: str,
        sender_pub_b64: str,
        content_sig: str,
        ts: int,
    ) -> None:
        session = self._user_sessions.get(target)
        if not session:
            return
        payload = {
            "from": sender,
            "ciphertext": ciphertext_b64,
            "sender_pub": sender_pub_b64,
            "content_sig": content_sig,
            "ts": ts,
        }
        await self._send_envelope(session.connection, "USER_DELIVER", target, payload, sign=False)

    async def _broadcast_public(
        self,
        sender: str,
        ciphertext_b64: str,
        sender_pub_b64: str,
        content_sig: str,
        ts: int,
    ) -> None:
        payload = {
            "from": sender,
            "group_id": "public",
            "ciphertext": ciphertext_b64,
            "sender_pub": sender_pub_b64,
            "content_sig": content_sig,
            "ts": ts,
        }
        for uid, session in self._user_sessions.items():
            await self._send_envelope(session.connection, "PUBLIC_DELIVER", uid, payload, sign=False)

    async def _deliver_file_local(self, target: str, frame_type: str, payload: Dict[str, Any]) -> None:
        session = self._user_sessions.get(target)
        if not session:
            return
        body = dict(payload)
        if "from" not in body:
            body["from"] = payload.get("sender") or session.user_id
        await self._send_envelope(session.connection, frame_type, target, body, sign=False)

    async def _send_public_state(self, session: UserSession) -> None:
        wrapped = crypto.b64url(crypto.rsa_encrypt_oaep(session.enc_pub, self.public_channel_key))
        self.public_wraps[session.user_id] = wrapped
        add_payload = {
            "group_id": "public",
            "member_id": session.user_id,
            "wrapped_key": wrapped,
            "version": self.public_version,
        }
        await self._send_envelope(session.connection, "PUBLIC_CHANNEL_ADD", session.user_id, add_payload, sign=False)
        update_payload = {
            "group_id": "public",
            "version": self.public_version,
            "wraps": [
                {"member_id": session.user_id, "wrapped_key": wrapped}
            ],
        }
        await self._send_envelope(session.connection, "PUBLIC_CHANNEL_UPDATED", session.user_id, update_payload, sign=False)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    async def _send_envelope(
        self,
        conn: Connection,
        type_: str,
        to: str,
        payload: Dict[str, Any],
        *,
        sign: bool = True,
    ) -> None:
        if sign:
            frame = proto.make_envelope(type_, self.server_id, to, payload, self._sign_transport)
        else:
            frame = proto.build_frame(type_, self.server_id, to, payload)
        await conn.send(frame)

    async def _send_error(self, conn: Connection, code: str, detail: str) -> None:
        payload = {"code": code, "detail": detail}
        target = conn.peer_id or "*"
        await self._send_envelope(conn, "ERROR", target, payload, sign=False)

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(max(1, self.heartbeat_secs))
            if self.peer_manager:
                self.peer_manager.tick_health(timeout_s=float(self.dead_after_secs))

    def _configure_backdoors(self) -> None:
        os.environ["VULN_WEAK_KEYS"] = "1" if self.vuln_weak_keys else "0"
        os.environ["VULN_REPLAY"] = "1" if self.vuln_replay else "0"

    def _ensure_server_keys(self) -> tuple[bytes, bytes]:
        priv, pub = crypto.ensure_rsa_pair(self.key_dir / "server_priv.pem", self.key_dir / "server_pub.pem")
        return priv, pub

    @staticmethod
    def _parse_listen(value: str) -> tuple[str, int]:
        host, port = value.split(":", 1)
        return host, int(port)

    @staticmethod
    def _fmt_remote(websocket: WebSocketServerProtocol) -> str:
        peer = websocket.remote_address
        if isinstance(peer, tuple):
            return f"{peer[0]}:{peer[1]}"
        return str(peer)

__all__ = ["ServerRuntime"]

