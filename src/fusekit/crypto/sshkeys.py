"""SSH/deploy key generation."""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass(frozen=True)
class SshKeyPair:
    """An OpenSSH Ed25519 key pair."""

    public_key: str
    private_key: str
    fingerprint: str


def generate_ed25519_keypair(comment: str) -> SshKeyPair:
    """Generate an Ed25519 deploy key pair."""

    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = private_key.public_key()
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    public_key = f"{public_bytes.decode('utf-8')} {comment}"
    fingerprint = base64.b64encode(public.public_bytes_raw()).decode("ascii")[:16]
    return SshKeyPair(
        public_key=public_key,
        private_key=private_bytes.decode("utf-8"),
        fingerprint=f"ed25519:{fingerprint}",
    )
