# sai-dh

[![sai-dh checks](https://github.com/saiset-co/sai-dh/actions/workflows/ci.yml/badge.svg)](https://github.com/saiset-co/sai-dh/actions/workflows/ci.yml)

Stateless P-256 ECDH and authenticated encryption for the saiSET ecosystem, built
on [`sai-service` v1.1.27](https://github.com/saiset-co/sai-service/tree/v1.1.27).
Module path: `github.com/saiset-co/sai-dh`.

This project has two entry points:

- `cmd/main.go`: a SAI HTTP service with configuration, lifecycle, health and API documentation.
- `pkg/dh`: a Go package with standard-library-only crypto, usable without running the HTTP service.

**Trust boundary:** the HTTP service receives private keys and plaintext and
returns private/derived keys to authorized callers. It is a trusted crypto
endpoint, not a blind relay or a key vault. For messenger end-to-end encryption,
execute `pkg/dh` on the user's device; never send private keys to a remote
SAI backend. This package does not yet include mobile bindings, an authenticated
handshake, a ratchet, replay tracking, encrypted group membership or a one-time pad.

See [validation status](docs/VALIDATION.md) for what has actually run and
[the review of the supplied sketch](docs/REVIEW.ru.md) for changes and limitations.

## Run locally

The module minimum is Go 1.24.2. Docker uses Go 1.27.1; CI also checks Go 1.24.11.
Sonic is explicitly upgraded within this module for current Go compatibility.

```sh
git clone https://github.com/saiset-co/sai-dh.git
cd sai-dh
go mod tidy
go run ./examples/local
export SAI_DH_TOKEN="$(openssl rand -hex 32)"
go run ./cmd -config config.yml
```

The default listener is `127.0.0.1:8083`. The binary does not automatically read
`.env`; export environment variables or use the Docker Compose instructions below.
It refuses to start without a valid auth configuration. No generated token is
printed or stored by the application.

To build an executable, run `make build`. From the project directory, set
`SAI_DH_TOKEN` and run `./bin/sai-dh -config config.yml`.
This builds a server binary; iOS/Android bindings are a separate integration step.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SAI_DH_HOST` | `127.0.0.1` | Listener IP; overrides `config.yml` |
| `SAI_DH_PORT` | `8083` | Listener port; overrides `config.yml` |
| `SAI_DH_AUTH_MODE` | `token` | `token` or `sai-auth` |
| `SAI_DH_TOKEN` | unset | Random service token, at least 32 characters |
| `SAI_DH_TOKEN_FILE` | unset | Alternative mounted token file; mutually exclusive with token env |
| `SAI_DH_AUTH_URL` | unset | Base URL for sai-auth mode |
| `SAI_DH_AUTH_TIMEOUT` | `3s` | Auth timeout, maximum `30s` |
| `SAI_DH_AUTH_ALLOW_HTTP` | `false` | Explicitly allow non-loopback HTTP to sai-auth on a trusted network |

`Authorization: Bearer TOKEN` and the SAI `Token: TOKEN` header are supported.
Supplying both is rejected. Tokens and cryptographic inputs are never accepted
in URL query parameters. Local HTTP is for loopback/trusted-network operation;
use TLS between hosts, with SAI TLS configuration or your reverse proxy.

## Docker

```sh
cp .env.example .env
# Set SAI_DH_TOKEN in .env to a newly generated random token.
docker compose up --build -d
docker compose ps
```

Compose publishes only to host loopback. The container runs as a non-root user
with a read-only filesystem and no application data volume. The built-in
`-healthcheck` command checks local HTTP; if enabling native SAI HTTPS, configure
an HTTPS-aware probe with your trusted CA instead. Database, cache and action
payload publishing must remain disabled for this stateless service.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Framework health, public |
| GET | `/version` | Framework version, public |
| GET | `/docs` | SAI generated API documentation |
| GET | `/api/v1/capabilities` | Explicit supported features and limitations; authenticated |
| POST | `/api/v1/keys/generate` | Generate P-256 keys; send `{}` |
| POST | `/api/v1/salts/generate` | Generate a 32-byte session salt; send `{}` |
| POST | `/api/v1/keys/derive` | Derive a 32-byte AES key with HKDF |
| POST | `/api/v1/encrypt` | Encrypt a UTF-8 message with AES-256-GCM |
| POST | `/api/v1/decrypt` | Authenticate and decrypt a versioned envelope |

All `/api/v1` routes require authentication and return `Cache-Control: no-store`.
POST requests require a single JSON object and `Content-Type: application/json`.
Unknown JSON fields are rejected. Empty messages are allowed (`message` defaults
to an empty string). Core limits: message 1 MiB, AAD 4096 bytes, context 1024
bytes; the complete encoded HTTP request must also fit the 4 MiB request limit.
These are byte limits, including UTF-8 encoding.

`docs/openapi.json` is a standalone OpenAPI 3.0 contract. Framework docs are
generated from the same request/response Go structs but may describe less strict
validation than the standalone contract.

Key generation response:

```json
{
  "suite": "SAI-DH-P256-HKDF-SHA256-AES256GCM-v1",
  "private_key": "64 hexadecimal characters",
  "public_key": "130 hexadecimal characters beginning with 04",
  "fingerprint": "SHA-256 of the encoded public key, in hexadecimal"
}
```

Derive request (Alice supplies Alice's private key and Bob's public key):

```json
{
  "private_key": "ALICE_PRIVATE_HEX",
  "public_key": "BOB_PUBLIC_HEX",
  "salt": "SHARED_SESSION_SALT_HEX",
  "context": "chat/123/session/456/alice-to-bob"
}
```

Bob supplies Bob's private key, Alice's public key and the same salt/context.
Both receive `{ "suite": "...", "key": "64 hexadecimal characters" }`.
Use a distinct, agreed context for the reverse direction and for other purposes.
Generate the salt once per session and share it; independently generating a salt
on each side will deliberately produce different keys. Salt is public, not secret.

Encrypt request:

```json
{
  "key": "DERIVED_KEY_HEX",
  "message": "Hello",
  "aad": "chat/123/message/789"
}
```

Response:

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "ciphertext": "HEX_NONCE_CIPHERTEXT_AND_TAG"
}
```

Decrypt with `{ "key": "...", "envelope": <the entire response above>, "aad": "..." }`.
The result is `{ "plaintext": "Hello" }`. AAD is authenticated but not encrypted
and must be identical on both sides. Wrong key, modified data, unsupported
version or wrong AAD return HTTP 400 without plaintext. Authorization service
failure returns 503; it never enables unauthenticated operation.

Use `pkg/dh` for arbitrary binary data rather than converting arbitrary bytes
to JSON text. The Go package's ciphertext format is the same nonce/ciphertext/tag
format used inside the hex-encoded HTTP envelope.

## saiSET integration

See [SAI integration](docs/SAI-INTEGRATION.md) for a client configuration,
sai-auth permission example, and deployment steps. The auth adapter uses the
existing `/api/v1/auth/verify` contract but sends an empty `request_params`
object. It never forwards the crypto payload. Authorization rules must therefore
grant method/path access; nonempty `modified_params` responses are rejected.

The provider is registered as `sai-dh-auth`. Every crypto route also invokes it
directly, so a missing/failed framework auth middleware cannot make the API open.
Request logging, response caching and compression are disabled on these routes.

## Test

```sh
make deps
make fmt
make check
python3 scripts/smoke.py --start ./bin/sai-dh
go test ./pkg/dh -run '^$' -fuzz '^FuzzDeriveKey$' -fuzztime=10s
go test ./pkg/dh -run '^$' -fuzz '^FuzzDecrypt$' -fuzztime=10s
```

Tests cover agreement, key/point validation, leading-zero ECDH output,
independent interoperability vectors, nonce randomization, modified nonce/body/tag,
wrong keys/AAD, input limits, concurrency, authentication failures and absence
of crypto payloads in authorization requests. The smoke test starts the actual
SAI server, exercises every crypto route and checks logs for its test secrets.

`scripts/reference_vectors.py` reproduces fixtures using Python
`cryptography`/OpenSSL. It is optional and separate from the service build.
The fixture private keys are deliberately public test values; never use them.

## Security boundaries

Read [the protocol specification](docs/PROTOCOL.md) before integrating.
ECDH itself does not authenticate the remote person. Fingerprints must be
verified through an authenticated mechanism. The application owns key storage,
key rotation, per-direction contexts, replay protection, device revocation and
the aggregate AES-GCM usage limit (strictly fewer than 2^32 encryptions per key).
This stateless service does not enforce a global per-key usage counter.

Fresh ephemeral keys and an authenticated session protocol are required for
forward secrecy; merely changing HKDF salt is not sufficient. Successful tests
are not a cryptographic audit or a claim of Telegram/Signal-level security.
Go memory and HTTP buffers may hold copies of secret material; clearing local
byte slices does not guarantee secure erasure or resistance to process compromise.

This repository does not yet declare a license. The organization must choose
one and review dependency notices before offering licensed redistribution.
