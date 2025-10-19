from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import websockets

from socp.core import crypto, proto

log = logging.getLogger("socp.cmd.client")


@dataclass
class DownloadState:
    sender: str
    name: str
    size: int
    sha256: str
    mode: str
    chunks: Dict[int, bytes] = field(default_factory=dict)

    def add_chunk(self, index: int, data: bytes) -> None:
        self.chunks[index] = data

    def assemble(self) -> bytes:
        return b"".join(self.chunks[i] for i in sorted(self.chunks))


class ClientApp:
    def __init__(self, server_url: str, user_id: str, key_dir: Path) -> None:
        self.server_url = server_url
        self.user_id = user_id
        self.key_dir = key_dir

        self.sign_priv, self.sign_pub = crypto.ensure_rsa_pair(
            key_dir / "sign_priv.pem", key_dir / "sign_pub.pem"
        )
        self.enc_priv, self.enc_pub = crypto.ensure_rsa_pair(
            key_dir / "enc_priv.pem", key_dir / "enc_pub.pem"
        )
        self.sign_transport = lambda payload: crypto.b64url(
            crypto.sign_pss_sha256(self.sign_priv, payload)
        )

        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.directory: Dict[str, Dict[str, Any]] = {}
        self.public_channel_key: Optional[bytes] = None
        self.downloads: Dict[str, DownloadState] = {}
        self.stop_event = asyncio.Event()

    async def run(self) -> None:
        async with websockets.connect(self.server_url) as ws:
            self.ws = ws
            await self._send_hello()
            receiver = asyncio.create_task(self._rx_loop())
            try:
                await self._command_loop()
            finally:
                self.stop_event.set()
                receiver.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await receiver

    async def _command_loop(self) -> None:
        loop = asyncio.get_running_loop()
        print("SOCP client ready. Commands: /list, /tell <user> <msg>, /all <msg>, /file <user> <path>, /quit")
        while not self.stop_event.is_set():
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                await self._handle_command(line)
            else:
                await self._cmd_all(line)

    async def _handle_command(self, line: str) -> None:
        parts = line.split()
        cmd = parts[0]
        if cmd == "/list":
            await self._send_frame("LIST_USERS", {})
        elif cmd == "/tell" and len(parts) >= 3:
            target = parts[1]
            text = line.split(" ", 2)[2]
            await self._cmd_tell(target, text)
        elif cmd == "/all" and len(parts) >= 2:
            text = line.split(" ", 1)[1]
            await self._cmd_all(text)
        elif cmd == "/file" and len(parts) >= 3:
            target = parts[1]
            path = Path(line.split(" ", 2)[2]).expanduser()
            await self._cmd_file(target, path)
        elif cmd in {"/quit", "/exit"}:
            self.stop_event.set()
        else:
            print("Unknown command")

    async def _rx_loop(self) -> None:
        assert self.ws is not None
        try:
            async for raw in self.ws:
                try:
                    env = proto.Envelope(**json.loads(raw))
                except Exception:
                    log.warning("Dropped invalid frame: %s", raw)
                    continue
                await self._handle_incoming(env)
        except websockets.ConnectionClosed:
            pass
        finally:
            self.stop_event.set()

    async def _handle_incoming(self, env: proto.Envelope) -> None:
        typ = env.type
        payload = env.payload
        if typ == "ACK":
            log.info("ACK: %s", payload)
        elif typ == "ERROR":
            print(f"ERROR ({payload.get('code')}): {payload.get('detail')}")
        elif typ == "LIST_USERS_RESULT":
            self._handle_list_users(payload)
        elif typ == "USER_DELIVER":
            await self._handle_user_deliver(payload)
        elif typ == "PUBLIC_CHANNEL_ADD":
            await self._handle_public_add(payload)
        elif typ == "PUBLIC_CHANNEL_UPDATED":
            await self._handle_public_update(payload)
        elif typ == "PUBLIC_DELIVER":
            await self._handle_public_deliver(payload)
        elif typ == "FILE_START":
            self._handle_file_start(payload)
        elif typ == "FILE_CHUNK":
            self._handle_file_chunk(payload)
        elif typ == "FILE_END":
            self._handle_file_end(payload)
        else:
            log.debug("Unhandled frame %s", typ)

    async def _send_hello(self) -> None:
        payload = {
            "client": self.user_id,
            "pubkey": crypto.b64url(self.sign_pub),
            "enc_pubkey": crypto.b64url(self.enc_pub),
            "meta": {"display_name": self.user_id},
        }
        await self._send_frame("USER_HELLO", payload, sign=False)

    async def _cmd_tell(self, target: str, text: str) -> None:
        entry = await self._ensure_directory_entry(target)
        if not entry:
            print("Unknown user. Run /list first.")
            return
        enc_key = crypto.b64url_decode(entry["enc_pubkey"])
        ciphertext = crypto.rsa_encrypt_oaep(enc_key, text.encode("utf-8"))
        ts = proto.now_ms()
        digest = crypto.content_digest_direct(ciphertext, self.user_id, target, ts)
        payload = {
            "to": target,
            "ciphertext": crypto.b64url(ciphertext),
            "sender_pub": crypto.b64url(self.sign_pub),
            "content_sig": crypto.sign_content(self.sign_priv, digest),
            "ts": ts,
            "hops": 0,
        }
        await self._send_frame("MSG_DIRECT", payload)

    async def _cmd_all(self, text: str) -> None:
        if not self.public_channel_key:
            print("Public channel key not yet received. Wait for join messages or /list again.")
            return
        ciphertext = crypto.aes_gcm_encrypt(self.public_channel_key, text.encode("utf-8"))
        ts = proto.now_ms()
        digest = crypto.content_digest_public(ciphertext, self.user_id, ts)
        payload = {
            "group_id": "public",
            "ciphertext": crypto.b64url(ciphertext),
            "sender_pub": crypto.b64url(self.sign_pub),
            "content_sig": crypto.sign_content(self.sign_priv, digest),
            "ts": ts,
            "sender": self.user_id,
        }
        await self._send_frame("MSG_PUBLIC_CHANNEL", payload)

    async def _cmd_file(self, target: str, path: Path) -> None:
        if not path.exists():
            print(f"File not found: {path}")
            return
        entry = await self._ensure_directory_entry(target)
        if not entry:
            print("Unknown user")
            return
        enc_key = crypto.b64url_decode(entry["enc_pubkey"])
        data = path.read_bytes()
        file_id = str(uuid.uuid4())
        sha256 = hashlib.sha256(data).hexdigest()
        payload = {
            "to": target,
            "file_id": file_id,
            "name": path.name,
            "size": len(data),
            "sha256": sha256,
            "mode": "dm",
        }
        await self._send_frame("FILE_START", payload)
        chunk_size = 190
        for index, offset in enumerate(range(0, len(data), chunk_size)):
            chunk = data[offset : offset + chunk_size]
            ciphertext = crypto.rsa_encrypt_oaep(enc_key, chunk)
            ts = proto.now_ms()
            digest = crypto.content_digest_direct(ciphertext, self.user_id, target, ts)
            chunk_payload = {
                "to": target,
                "file_id": file_id,
                "index": index,
                "ciphertext": crypto.b64url(ciphertext),
                "sender_pub": crypto.b64url(self.sign_pub),
                "content_sig": crypto.sign_content(self.sign_priv, digest),
                "ts": ts,
            }
            await self._send_frame("FILE_CHUNK", chunk_payload)
        await self._send_frame("FILE_END", {"to": target, "file_id": file_id})
        print(f"Sent file {path} to {target}")

    async def _ensure_directory_entry(self, user_id: str) -> Optional[Dict[str, Any]]:
        entry = self.directory.get(user_id)
        if entry:
            return entry
        await self._send_frame("LIST_USERS", {})
        await asyncio.sleep(0.2)
        return self.directory.get(user_id)

    async def _send_frame(self, type_: str, payload: Dict[str, Any], *, sign: bool = True) -> None:
        assert self.ws is not None
        if sign:
            frame = proto.make_envelope(type_, self.user_id, "*", payload, self.sign_transport)
        else:
            frame = proto.build_frame(type_, self.user_id, "*", payload)
        await self.ws.send(json.dumps(frame, separators=(",", ":")))

    def _handle_list_users(self, payload: Dict[str, Any]) -> None:
        users = payload.get("users", [])
        for entry in users:
            uid = entry.get("user_id")
            if uid:
                self.directory[uid] = entry
        names = ", ".join(sorted(self.directory))
        print(f"Online: {names}")

    async def _handle_user_deliver(self, payload: Dict[str, Any]) -> None:
        sender = payload.get("from")
        ciphertext_b64 = payload.get("ciphertext")
        if not sender or not ciphertext_b64:
            return
        try:
            ciphertext = crypto.b64url_decode(ciphertext_b64)
            plaintext = crypto.rsa_decrypt_oaep(self.enc_priv, ciphertext)
        except Exception as exc:
            log.warning("Failed to decrypt DM from %s: %s", sender, exc)
            return
        print(f"[{sender}] {plaintext.decode('utf-8', errors='replace')}")

    async def _handle_public_add(self, payload: Dict[str, Any]) -> None:
        wraps = []
        member = payload.get("member_id")
        wrapped = payload.get("wrapped_key")
        if member and wrapped:
            wraps.append({"member_id": member, "wrapped_key": wrapped})
        await self._handle_public_update({"wraps": wraps})

    async def _handle_public_update(self, payload: Dict[str, Any]) -> None:
        wraps = payload.get("wraps", [])
        for wrap in wraps:
            if wrap.get("member_id") != self.user_id:
                continue
            wrapped_key_b64 = wrap.get("wrapped_key")
            if not wrapped_key_b64:
                continue
            try:
                wrapped = crypto.b64url_decode(wrapped_key_b64)
                key = crypto.rsa_decrypt_oaep(self.enc_priv, wrapped)
            except Exception as exc:
                log.warning("Failed to unwrap public key: %s", exc)
                continue
            self.public_channel_key = key
            print("[public] channel key updated")

    async def _handle_public_deliver(self, payload: Dict[str, Any]) -> None:
        if not self.public_channel_key:
            return
        sender = payload.get("from")
        ciphertext_b64 = payload.get("ciphertext")
        if not sender or not ciphertext_b64:
            return
        try:
            ciphertext = crypto.b64url_decode(ciphertext_b64)
            plaintext = crypto.aes_gcm_decrypt(self.public_channel_key, ciphertext)
        except Exception as exc:
            log.warning("Failed to decrypt public message: %s", exc)
            return
        print(f"[all:{sender}] {plaintext.decode('utf-8', errors='replace')}")

    def _handle_file_start(self, payload: Dict[str, Any]) -> None:
        file_id = payload.get("file_id")
        if not file_id:
            return
        state = DownloadState(
            sender=payload.get("from", ""),
            name=payload.get("name", f"{file_id}.bin"),
            size=int(payload.get("size", 0)),
            sha256=payload.get("sha256", ""),
            mode=payload.get("mode", "dm"),
        )
        self.downloads[file_id] = state
        print(f"[file] receiving {state.name} from {state.sender}")

    def _handle_file_chunk(self, payload: Dict[str, Any]) -> None:
        file_id = payload.get("file_id")
        state = self.downloads.get(file_id)
        if not state:
            return
        index = int(payload.get("index", 0))
        ciphertext_b64 = payload.get("ciphertext")
        if not ciphertext_b64:
            return
        try:
            ciphertext = crypto.b64url_decode(ciphertext_b64)
            chunk = crypto.rsa_decrypt_oaep(self.enc_priv, ciphertext)
        except Exception:
            return
        state.add_chunk(index, chunk)

    def _handle_file_end(self, payload: Dict[str, Any]) -> None:
        file_id = payload.get("file_id")
        state = self.downloads.pop(file_id, None)
        if not state:
            return
        data = state.assemble()
        download_dir = self.key_dir / "downloads"
        download_dir.mkdir(parents=True, exist_ok=True)
        dest = download_dir / state.name
        dest.write_bytes(data)
        print(f"[file] saved {state.name} -> {dest}")


async def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="SOCP client")
    parser.add_argument("--server", required=True, help="ws://host:port of SOCP server")
    parser.add_argument("--user", dest="user_id", required=False, default=None, help="User identifier (UUIDv4 if omitted)")
    parser.add_argument("--keys-dir", default="~/.socp", help="Directory to store client keys")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    user_id = args.user_id or str(uuid.uuid4())
    key_dir = Path(args.keys_dir).expanduser() / user_id
    key_dir.mkdir(parents=True, exist_ok=True)

    app = ClientApp(args.server, user_id, key_dir)
    await app.run()


if __name__ == "__main__":
    asyncio.run(main())
