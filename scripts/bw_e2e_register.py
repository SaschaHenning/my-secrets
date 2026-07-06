#!/usr/bin/env python3
"""Register a Bitwarden/Vaultwarden account for E2E tests.

Implements the client-side registration crypto (PBKDF2 master key,
HKDF-stretched key, AES-256-CBC + HMAC "2.iv|ct|mac" enc-strings, RSA
keypair) against the legacy /identity/accounts/register endpoint that
Vaultwarden still serves. Only intended for throwaway test instances.

Usage: BW_E2E_PASSWORD=<pw> bw_e2e_register.py <server-url> <email> [ca-cert.pem]

The password comes from the environment, never argv (ps-visible).
"""
import base64
import os
import sys

import requests
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ITERATIONS = 600_000


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def pbkdf2(secret: bytes, salt: bytes, iterations: int, length: int = 32) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), length, salt, iterations).derive(secret)


def hkdf_expand(key: bytes, info: str, length: int = 32) -> bytes:
    return HKDFExpand(hashes.SHA256(), length, info.encode()).derive(key)


def enc_string(data: bytes, enc_key: bytes, mac_key: bytes) -> str:
    """Bitwarden EncString type 2: AES-256-CBC + HMAC-SHA256 over iv||ct."""
    iv = os.urandom(16)
    pad = 16 - len(data) % 16
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = cipher.update(data + bytes([pad]) * pad) + cipher.finalize()
    mac = hmac.HMAC(mac_key, hashes.SHA256())
    mac.update(iv + ct)
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac.finalize())}"


def main() -> None:
    if len(sys.argv) < 3 or not os.environ.get("BW_E2E_PASSWORD"):
        sys.exit(__doc__)
    url, email = sys.argv[1], sys.argv[2]
    password = os.environ["BW_E2E_PASSWORD"]
    verify = sys.argv[3] if len(sys.argv) > 3 else True

    master = pbkdf2(password.encode(), email.lower().encode(), KDF_ITERATIONS)
    payload_hash = b64(pbkdf2(master, password.encode(), 1))
    enc_key, mac_key = hkdf_expand(master, "enc"), hkdf_expand(master, "mac")
    sym = os.urandom(64)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_der = rsa_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_der = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {
        "name": "mys e2e",
        "email": email,
        "masterPasswordHash": payload_hash,
        "masterPasswordHint": None,
        "key": enc_string(sym, enc_key, mac_key),
        "kdf": 0,
        "kdfIterations": KDF_ITERATIONS,
        "keys": {
            "publicKey": b64(pub_der),
            "encryptedPrivateKey": enc_string(priv_der, sym[:32], sym[32:]),
        },
    }
    r = requests.post(
        f"{url}/identity/accounts/register", json=payload, timeout=30, verify=verify
    )
    r.raise_for_status()
    print(f"registered {email} at {url}")


if __name__ == "__main__":
    main()
