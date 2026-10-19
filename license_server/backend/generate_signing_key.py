#!/usr/bin/env python3
"""Generate an Ed25519 signing key pair for EncoreDLC.

Store PRIVATE_B64URL only in the backend secret manager/environment.
Embed PUBLIC_B64URL in the client at build time. Never ship the private key.
"""
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

private = Ed25519PrivateKey.generate()
private_raw = private.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
public_raw = private.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print("ENDLC_SIGNING_PRIVATE_KEY_B64=" + b64u(private_raw))
print("PUBLIC_B64URL=" + b64u(public_raw))
print("\nIMPORTANT: keep the private value secret; never include it in an APK/repository.")
