#!/usr/bin/env python3
"""Reproduce interoperability fixtures with Python cryptography/OpenSSL.

This verifies the wire/KDF specification independently; it does not execute or
test the Go implementation. Test private keys are deterministic public fixtures.
Run with --write to regenerate testdata; without it, verify the committed data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SUITE = b"SAI-DH-P256-HKDF-SHA256-AES256GCM-v1"
TARGET = Path(__file__).resolve().parents[1] / "pkg/dh/testdata/vectors.json"


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def fixture(name, scalar_a, scalar_b):
    a = ec.derive_private_key(scalar_a, ec.SECP256R1())
    b = ec.derive_private_key(scalar_b, ec.SECP256R1())
    shared = a.exchange(ec.ECDH(), b.public_key())
    assert shared == b.exchange(ec.ECDH(), a.public_key()) and len(shared) == 32
    salt = bytes(range(32))
    context = "vector/session-1/alice-to-bob"
    p1, p2 = sorted([public(a), public(b)])
    info = SUITE + b"\0" + p1 + p2 + struct.pack(">I", len(context.encode())) + context.encode()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared)
    nonce = bytes(range(12))  # Fixed nonce ONLY in this published test fixture.
    aad = "vector/message-1"
    plaintext = "hello, שלום, €".encode()
    encrypted = AESGCM(key).encrypt(nonce, plaintext, aad.encode())
    assert AESGCM(key).decrypt(nonce, encrypted, aad.encode()) == plaintext
    return {
        "name": name,
        "private_a": scalar_a.to_bytes(32, "big").hex(), "public_a": public(a).hex(),
        "private_b": scalar_b.to_bytes(32, "big").hex(), "public_b": public(b).hex(),
        "salt": salt.hex(), "context": context, "key": key.hex(),
        "aad": aad, "plaintext_hex": plaintext.hex(), "ciphertext": (nonce + encrypted).hex(),
        "raw_shared_secret": shared.hex(), "fingerprint_a": hashlib.sha256(public(a)).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    # Scalar 1 exposes the peer X coordinate as ECDH output. Find a leading-zero
    # X to catch the original big.Int.Bytes() variable-length output problem.
    leading_zero = next(n for n in range(2, 10000) if public(ec.derive_private_key(n, ec.SECP256R1()))[1] == 0)
    vectors = [fixture("basic", 1, 2), fixture("leading-zero-shared-secret", 1, leading_zero)]
    assert vectors[1]["raw_shared_secret"].startswith("00")
    if args.write:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_text(json.dumps(vectors, indent=2) + "\n")
    else:
        assert json.loads(TARGET.read_text()) == vectors, "fixture mismatch"
    print("PASS: independent P-256/HKDF/AES-GCM vectors, including leading-zero ECDH output")


if __name__ == "__main__":
    main()
