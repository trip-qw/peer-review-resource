from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_B64_PAD = {0: "", 2: "==", 3: "="}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    pad = _B64_PAD[len(value) % 4]
    return base64.urlsafe_b64decode(value + pad)


def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


def load_private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def rsa_encrypt_oaep(pubkey_pem: bytes, plaintext: bytes) -> bytes:
    pub = load_public_key(pubkey_pem)
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_oaep(privkey_pem: bytes, ciphertext: bytes) -> bytes:
    priv = load_private_key(privkey_pem)
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign_pss_sha256(privkey_pem: bytes, message: bytes) -> bytes:
    priv = load_private_key(privkey_pem)
    return priv.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_pss_sha256(pubkey_pem: bytes, message: bytes, signature: bytes) -> bool:
    pub = load_public_key(pubkey_pem)
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def accept_pubkey(pubkey_pem: bytes) -> bool:
    allow_weak = os.getenv("VULN_WEAK_KEYS", "0") == "1"
    pub = load_public_key(pubkey_pem)
    if isinstance(pub, rsa.RSAPublicKey):
        size = pub.key_size
        if allow_weak and size >= 1024:
            return True
        return size >= 4096
    return False


def ensure_rsa_pair(private_path: Path | str, public_path: Path | str) -> Tuple[bytes, bytes]:
    priv_path = Path(private_path)
    pub_path = Path(public_path)
    if priv_path.exists() and pub_path.exists():
        return priv_path.read_bytes(), pub_path.read_bytes()

    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    priv_bytes = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)
    return priv_bytes, pub_bytes


def aes_gcm_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 128/192/256-bit")
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, blob: bytes, *, aad: bytes = b"") -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 128/192/256-bit")
    nonce, ciphertext = blob[:12], blob[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)


def _digest(*parts: bytes) -> bytes:
    hasher = hashes.Hash(hashes.SHA256())
    for part in parts:
        hasher.update(part)
    return hasher.finalize()


def content_digest_direct(ciphertext: bytes, from_id: str, to_id: str, ts: int) -> bytes:
    return _digest(ciphertext, from_id.encode(), to_id.encode(), str(ts).encode())


def content_digest_public(ciphertext: bytes, from_id: str, ts: int) -> bytes:
    return _digest(ciphertext, from_id.encode(), str(ts).encode())


def content_digest_key_share(shares_blob: bytes, creator_pub: bytes) -> bytes:
    return _digest(shares_blob, creator_pub)


def sign_content(privkey_pem: bytes, digest: bytes) -> str:
    return b64url(sign_pss_sha256(privkey_pem, digest))


def verify_content_signature(pubkey_pem: bytes, digest: bytes, signature_b64: str) -> bool:
    try:
        signature = b64url_decode(signature_b64)
    except Exception:
        return False
    return verify_pss_sha256(pubkey_pem, digest, signature)


__all__ = [
    "b64url",
    "b64url_decode",
    "rsa_encrypt_oaep",
    "rsa_decrypt_oaep",
    "sign_pss_sha256",
    "verify_pss_sha256",
    "accept_pubkey",
    "ensure_rsa_pair",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "content_digest_direct",
    "content_digest_public",
    "content_digest_key_share",
    "sign_content",
    "verify_content_signature",
]
