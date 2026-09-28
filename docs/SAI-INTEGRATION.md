# Adding sai-dh to saiSET

This is an independent service module using the existing SAI framework. No
changes to `sai-service`, `sai-auth`, `sai-crud` or `sai-storage` are required.
Deployment and registration in a running saiSET installation are separate from
publishing the source repository.

## Repository

Repository: [saiset-co/sai-dh](https://github.com/saiset-co/sai-dh).

Clone it and follow the README to run the service. The module path is
`github.com/saiset-co/sai-dh`. Check the included GitHub Actions workflow before
tagging a release. When maintaining a fork under another module path, update
the `module` line and local imports together.

## Service deployment

Run it on your existing container network. The example Compose file uses host
loopback for local testing; other containers should access `http://sai-dh:8083`
on an explicitly shared private Docker network. For traffic between hosts, use
HTTPS and your existing certificate management. Do not expose the crypto service
as an unauthenticated public key-generation/encryption endpoint.

Keep cryptographic bodies and authorization headers out of reverse-proxy access
logs, request tracing, APM payload capture and response caches. The service
itself disables framework payload logging but cannot control external collectors.

The included rate limiter is an in-process/IP-level SAI middleware. For multiple
replicas, enforce global/user-level limits at the gateway. Health checks do not
prove that the external sai-auth service is reachable; a failed verification
request returns 503 and denies the crypto operation.

## Calling from another SAI service

Add this under the caller's `clients.services` (replace the token at deploy time):

```yaml
clients:
  enabled: true
  services:
    dh:
      url: "http://sai-dh:8083"
      auth:
        provider: "token"
        payload:
          token: "INJECT_SECRET_AT_DEPLOY_TIME"
```

The existing SAI token provider sends a `Token` header, which sai-dh accepts.
Use `ClientManager.CallWithContext` as in the existing sai-crud service:

```go
body, _, err := sai.ClientManager().CallWithContext(
    ctx, "dh", "POST", "/api/v1/salts/generate", map[string]any{}, nil,
)
```

This demonstrates public-salt generation. If using remote derive/encrypt APIs,
the caller and sai-dh server are both inside the secret trust boundary. A
messenger that requires an untrusted/blind backend must instead use client-side
`pkg/dh` and must never route private keys through this API.

## sai-auth mode

```sh
export SAI_DH_AUTH_MODE=sai-auth
export SAI_DH_AUTH_URL=https://your-auth-service
go run ./cmd
```

The adapter calls `POST /api/v1/auth/verify` with precisely:

```json
{
  "token": "CALLER_ACCESS_TOKEN",
  "microservice": "sai-dh",
  "method": "POST",
  "path": "/api/v1/keys/derive",
  "request_params": {}
}
```

No private keys, shared keys, plaintext, ciphertext, salt, AAD or original query
parameters are forwarded. The existing auth provider's extraction of whole JSON
bodies is intentionally not reused for this secret-bearing service.

Grant permissions by service/method/path. Example role payload (review and apply
through your existing role administration; this file is not applied automatically):

```json
{
  "name": "sai_dh_client",
  "permissions": [
    {"microservice":"sai-dh","method":"GET","path":"/api/v1/capabilities"},
    {"microservice":"sai-dh","method":"POST","path":"/api/v1/keys/generate"},
    {"microservice":"sai-dh","method":"POST","path":"/api/v1/salts/generate"},
    {"microservice":"sai-dh","method":"POST","path":"/api/v1/keys/derive"},
    {"microservice":"sai-dh","method":"POST","path":"/api/v1/encrypt"},
    {"microservice":"sai-dh","method":"POST","path":"/api/v1/decrypt"}
  ]
}
```

No crypto-payload-scoped permissions are supported. Nonempty `modified_params`
are rejected so the application cannot accidentally ignore a scope restriction.
Do not substitute a superuser token into a client application.

## Compatibility

The dependency version reviewed is `sai-service` v1.1.27, commit
`5ac04d3e8fde15d8b60ab81fed5a9b9245d11fb5`.
The framework's current main commit at inspection was
`22431338bf29aa0b7fd508d2926f57880f12e8a8`; the Go source used by this service is
the same between that main snapshot and the pinned release.

The framework declares Go 1.24.2 and pins Sonic v1.13.3, which failed to compile
on Go 1.27.1 (`undefined: GoMapIterator`). This module explicitly upgrades Sonic
to v1.15.3, its loader to v0.5.2 and base64x to v0.1.6; gopkg v0.1.3 is added
transitively. These dependency selections apply to sai-dh only. No source changes
were made in existing saiSET repositories. Docker builds use Go 1.27.1; the CI
matrix also covers Go 1.24.11 for compatibility. See VALIDATION.md for results.
