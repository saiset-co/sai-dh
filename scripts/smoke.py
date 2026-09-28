#!/usr/bin/env python3
"""Exercise the actual SAI HTTP server. No keys or plaintext are printed.

python3 scripts/smoke.py --start ./bin/sai-dh
SAI_DH_TOKEN=... python3 scripts/smoke.py --url http://127.0.0.1:8083
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def call(base, path, payload=None, token=None, expected=200, method=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(base + path, body, headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.status
        raw = response.read()
        assert status == expected, f"{path}: expected {expected}, got {status}"
        if path.startswith("/api/v1/"):
            assert response.headers.get("Cache-Control") == "no-store", "missing no-store"
        return json.loads(raw)


def exercise(base, token):
    caps = call(base, "/api/v1/capabilities", token=token)
    assert caps["stateless"] and not caps["one_time_pad"]
    assert not caps["peer_authentication"] and not caps["replay_protection"]
    for path in ["/keys/generate", "/salts/generate", "/keys/derive", "/encrypt", "/decrypt"]:
        call(base, "/api/v1" + path, {}, expected=401)
    call(base, "/api/v1/keys/generate", {"unexpected": "field"}, token, expected=400)
    alice = call(base, "/api/v1/keys/generate", {}, token)
    bob = call(base, "/api/v1/keys/generate", {}, token)
    assert len(alice["private_key"]) == 64 and len(alice["public_key"]) == 130
    salt = call(base, "/api/v1/salts/generate", {}, token)["salt"]
    context = "smoke/session-1/alice-to-bob"

    def derive(own, peer):
        return call(base, "/api/v1/keys/derive", {
            "private_key": own["private_key"], "public_key": peer["public_key"],
            "salt": salt, "context": context,
        }, token)["key"]

    alice_key, bob_key = derive(alice, bob), derive(bob, alice)
    assert alice_key == bob_key and len(alice_key) == 64, "key agreement failed"
    message = "Smoke test: hello, שלום, €"
    aad = "smoke/session-1/message-1"
    envelope = call(base, "/api/v1/encrypt", {"key": alice_key, "message": message, "aad": aad}, token)
    plaintext = call(base, "/api/v1/decrypt", {"key": bob_key, "envelope": envelope, "aad": aad}, token)
    assert plaintext["plaintext"] == message
    call(base, "/api/v1/decrypt", {"key": bob_key, "envelope": envelope, "aad": "wrong"}, token, expected=400)
    damaged = dict(envelope)
    last = int(damaged["ciphertext"][-2:], 16) ^ 1
    damaged["ciphertext"] = damaged["ciphertext"][:-2] + f"{last:02x}"
    call(base, "/api/v1/decrypt", {"key": bob_key, "envelope": damaged, "aad": aad}, token, expected=400)
    damaged["version"] = 0
    call(base, "/api/v1/decrypt", {"key": bob_key, "envelope": damaged, "aad": aad}, token, expected=400)
    call(base, "/api/v1/keys/derive", {
        "private_key": "00" * 32, "public_key": bob["public_key"], "salt": salt, "context": context,
    }, token, expected=400)
    return [alice["private_key"], bob["private_key"], alice_key, bob_key, message]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", help="start this local sai-dh binary with a random token and port")
    parser.add_argument("--url", default="http://127.0.0.1:8083")
    args = parser.parse_args()
    process = None
    log_file = None
    if args.start:
        token = secrets.token_hex(32)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env.pop("SAI_DH_TOKEN_FILE", None)
        env.update(SAI_DH_TOKEN=token, SAI_DH_HOST="127.0.0.1", SAI_DH_PORT=str(port), SAI_DH_AUTH_MODE="token")
        log_file = tempfile.TemporaryFile(mode="w+b")
        process = subprocess.Popen([str(Path(args.start).resolve()), "-config", "config.yml"], env=env, stdout=log_file, stderr=subprocess.STDOUT)
    else:
        base = args.url.rstrip("/")
        token = os.environ.get("SAI_DH_TOKEN", "")
        if not token:
            raise SystemExit("Set SAI_DH_TOKEN or use --start")
    try:
        if process:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("SAI server exited before becoming ready")
                try:
                    call(base, "/health")
                    break
                except (OSError, ValueError, AssertionError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("SAI server did not become ready")
            probe = subprocess.run([str(Path(args.start).resolve()), "-healthcheck"], env=env, capture_output=True, timeout=3)
            assert probe.returncode == 0, "packaged healthcheck command failed"
        sensitive_values = exercise(base, token)
        if process:
            process.terminate()
            process.wait(timeout=15)
            assert process.returncode == 0, "service did not shut down cleanly"
            log_file.seek(0)
            logs = log_file.read()
            for value in [token] + sensitive_values:
                assert value.encode() not in logs, "sensitive value found in service logs"
        print("PASS: actual SAI HTTP routes, auth, agreement, encryption, tampering, version checks and log redaction")
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
