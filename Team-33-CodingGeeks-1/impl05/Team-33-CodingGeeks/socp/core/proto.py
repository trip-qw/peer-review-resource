from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Tuple, Union, Callable

from pydantic import BaseModel, Field, ConfigDict, field_validator


# ---------------------------------------------------------------------------
# Envelope model & helpers (SOCP transport layer)
# ---------------------------------------------------------------------------

class Envelope(BaseModel):
    """JSON envelope carried over WebSockets as per SOCP v1.3."""

    type: str
    from_: str = Field(alias="from")
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: str = ""

    model_config = ConfigDict(populate_by_name=True)

    @field_validator("ts")
    @classmethod
    def _ts_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("timestamp must be non-negative")
        return value


ERROR_CODES = {
    "USER_NOT_FOUND",
    "INVALID_SIG",
    "BAD_KEY",
    "TIMEOUT",
    "UNKNOWN_TYPE",
    "NAME_IN_USE",
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def now_ms() -> int:
    """Milliseconds since the Unix epoch."""

    return int(time.time() * 1000)


def is_uuid_v4(value: str) -> bool:
    try:
        return uuid.UUID(str(value)).version == 4
    except Exception:
        return False


def canonical_payload_bytes(payload: Dict[str, Any]) -> bytes:
    """Canonical JSON encoding used for transport signatures."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Frame construction & signing
# ---------------------------------------------------------------------------

SignFn = Callable[[bytes], str]
VerifyFn = Callable[[bytes, str], bool]


def build_frame(
    type: str,
    from_: str,
    to: str,
    payload: Dict[str, Any],
    *,
    ts: int | None = None,
) -> Dict[str, Any]:
    """Create an unsigned envelope dict."""

    return {
        "type": type,
        "from": from_,
        "to": to,
        "ts": now_ms() if ts is None else ts,
        "payload": payload,
        "sig": "",
    }


def sign_frame_in_place(frame: Dict[str, Any], sign_transport: SignFn) -> Dict[str, Any]:
    if "payload" not in frame:
        raise ValueError("frame missing payload")
    frame["sig"] = sign_transport(canonical_payload_bytes(frame["payload"]))
    return frame


def make_envelope(
    type: str,
    from_: str,
    to: str,
    payload: Dict[str, Any],
    sign_transport: SignFn,
    *,
    ts: int | None = None,
) -> Dict[str, Any]:
    """Build + sign a transport envelope."""

    frame = build_frame(type, from_, to, payload, ts=ts)
    return sign_frame_in_place(frame, sign_transport)


# ---------------------------------------------------------------------------
# Validation / verification
# ---------------------------------------------------------------------------


def validate_envelope(
    envelope: Union[Envelope, Dict[str, Any]],
    *,
    allow_ip_port_to: bool = False,
    expect_sig: bool = True,
) -> Dict[str, Any]:
    """Raise ValueError on structural issues, return dict representation otherwise."""

    env = envelope.model_dump(by_alias=True) if isinstance(envelope, Envelope) else dict(envelope)

    for key in ("type", "from", "to", "ts", "payload", "sig"):
        if key not in env:
            raise ValueError(f"missing field: {key}")

    if not isinstance(env["type"], str) or not env["type"]:
        raise ValueError("invalid type")
    if not isinstance(env["ts"], int):
        raise ValueError("ts must be int")
    if not isinstance(env["payload"], dict):
        raise ValueError("payload must be object")

    if not is_uuid_v4(env["from"]):
        raise ValueError("from must be UUID v4")

    to_value = env["to"]
    if to_value != "*" and not is_uuid_v4(to_value):
        if not (allow_ip_port_to and _looks_like_ip_port(to_value)):
            raise ValueError("invalid 'to'")

    if expect_sig and not env.get("sig"):
        raise ValueError("signature required")

    return env


def verify_envelope(
    envelope: Union[Envelope, Dict[str, Any]],
    verify_transport: VerifyFn,
    *,
    allow_ip_port_to: bool = False,
    expect_sig: bool = True,
) -> Tuple[bool, str | None]:
    try:
        env = validate_envelope(envelope, allow_ip_port_to=allow_ip_port_to, expect_sig=expect_sig)
    except ValueError:
        return False, "BAD_KEY"

    sig = env.get("sig", "")
    if not sig:
        return True, None  # permissible if expect_sig=False

    ok = verify_transport(canonical_payload_bytes(env["payload"]), sig)
    return (True, None) if ok else (False, "INVALID_SIG")


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    import base64

    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _looks_like_ip_port(value: str) -> bool:
    if not isinstance(value, str) or ":" not in value:
        return False
    host, port = value.rsplit(":", 1)
    return bool(host) and port.isdigit()


__all__ = [
    "Envelope",
    "ERROR_CODES",
    "now_ms",
    "is_uuid_v4",
    "build_frame",
    "sign_frame_in_place",
    "make_envelope",
    "validate_envelope",
    "verify_envelope",
    "canonical_payload_bytes",
    "b64url",
    "b64url_decode",
]
