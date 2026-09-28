# Validation record

Local validation snapshot: 2026-09-08. Platform: Linux x86-64.
Remote CI results are tracked separately in
[GitHub Actions](https://github.com/saiset-co/sai-dh/actions/workflows/ci.yml).

## Passed

| Check | Result |
| --- | --- |
| Go 1.27.1 `go test -race -count=1 ./...` | All four test packages passed; no data races reported |
| Go 1.27.1 `go vet ./...` | Passed |
| Go 1.24.11 `go test -count=1 ./...` after Sonic upgrade | All test packages passed |
| Go 1.24.11 race tests before the dependency compatibility update | Passed |
| P-256/HKDF/AES-GCM interoperability vectors | Generated independently with Python cryptography/OpenSSL; compared by the Go test suite |
| Leading-zero ECDH output regression | Passed with a public deterministic scalar fixture |
| ECDH input fuzzing, Go 1.24.11, 10 seconds | 469,261 executions; no failures |
| Decryption input fuzzing, Go 1.24.11, 10 seconds | 524,053 executions; no failures |
| Local Go crypto package example | Agreement and authenticated decryption passed |
| Go syntax and formatting | Parsed, compiled and formatted with gofmt |
| OpenAPI route mapping | All six documented API paths match registered routes |
| YAML and Python scripts | Configuration/CI parsed; scripts compiled |
| Static Linux executable | Built from this source using Go 1.27.1, CGO disabled |
| Actual SAI HTTP integration, Go 1.27.1 | Every crypto route, healthcheck and clean shutdown passed; no test secrets found in service logs |
| Module checksums | `go mod verify` passed |

The fuzz checks cover the crypto package, whose source did not change during
the Sonic upgrade. Fuzzing is bounded testing, not proof that no malformed input
can ever cause a failure.

The separately supplied source/binary archive includes a `release-manifest.json`
with its binary checksum. Build artifacts and their manifests are excluded from
the source repository. The HTTP smoke test covers actual SAI routing, all crypto endpoints, missing auth, unknown
JSON fields, key agreement, non-ASCII plaintext, wrong AAD, tampering, envelope
version rejection, zero private keys, the packaged healthcheck, clean shutdown
and absence of its test secrets from service logs.

## Not executed / not included

- Docker image build/run: Docker is not installed in this workspace. The
  Dockerfile and Compose configuration are included; the CI includes the image build.
- Remote CI is not part of this local validation snapshot; use the GitHub Actions
  link above for each commit's result.
- Integration with your running sai-auth instance: its HTTP contract was tested
  against a local test server, including denial, malformed responses, redirects,
  oversized responses and omission of crypto inputs. Existing remote roles were not changed.
- Independent cryptographic audit, load/soak testing, mobile bindings, authenticated
  handshake, ratchet, replay persistence, group rekeying and one-time-pad management.

## Dependency compatibility issue resolved

With the framework's original Sonic v1.13.3, Go 1.27.1 compilation failed with
`undefined: GoMapIterator`. The module now pins Sonic v1.15.3 and compatible
transitive dependencies, while retaining sai-service v1.1.27 unchanged. The final
module graph passed on both toolchains listed above. This is a targeted
compatibility fix, not a comprehensive vulnerability/dependency audit.

## Source and artifact provenance

Original uploaded `dh.go` SHA-256:
`ae6807be2907a9ce8015f643f649d4dc975f2b57388c839592efffad2a25bcd0`.

The supplied ELF file named `main` was identified by file type but never executed
or redistributed. The archive's `bin/sai-dh` is the newly built executable. No live keys,
credentials, user messages or `.env` files are included. Published deterministic
keys in `pkg/dh/testdata` are test fixtures only.
