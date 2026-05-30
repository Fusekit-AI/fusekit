"""OCI API signing key helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class OciSigningKeyPair:
    """OCI API signing key pair."""

    private_key_pem: str
    public_key_pem: str
    fingerprint: str


def generate_oci_signing_key_pair() -> OciSigningKeyPair:
    """Generate an RSA key pair suitable for OCI API request signing."""

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    fingerprint = _oci_fingerprint(public_pem)
    return OciSigningKeyPair(private_pem, public_pem, fingerprint)


def _oci_fingerprint(public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.md5(der, usedforsecurity=False).hexdigest()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))
