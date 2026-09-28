# Cryptographic contract v1

This is a specification of the implemented primitive composition, not a complete
messaging protocol and not an interoperability claim with Telegram or Signal.

## Key encoding

- Curve: NIST P-256, also called secp256r1/prime256v1.
- Private key: 32-byte big-endian scalar `d`, where `1 <= d < n`.
- Public key: SEC 1 uncompressed encoding, `0x04 || X[32] || Y[32]`.
- HTTP encoding: hexadecimal; uppercase input is accepted, output is lowercase.
- Fingerprint: lowercase hex SHA-256 of the full 65-byte public-key encoding.

Generation and import use Go `crypto/ecdh`, including scalar/point validation.
The fingerprint is an identifier for out-of-band verification, not a Bitcoin address.

## ECDH and HKDF

1. Validate the private key and peer public key with `crypto/ecdh.P256()`.
2. Compute ECDH shared secret `Z`. Preserve its fixed 32-byte encoding, including leading zeroes.
3. Require a 32-byte public session salt and a nonempty context (1..1024 UTF-8 bytes at the API boundary).
4. Obtain the two full encoded public keys, sort them lexicographically as bytes, call them `P0` and `P1`.
5. Construct `info` by concatenating:
   - ASCII `SAI-DH-P256-HKDF-SHA256-AES256GCM-v1`;
   - one zero byte;
   - `P0` (65 bytes);
   - `P1` (65 bytes);
   - the context length in bytes as an unsigned 32-bit big-endian integer;
   - the exact context bytes, with no Unicode normalization.
6. Compute a 32-byte output using HKDF-SHA256 with input key material `Z`, the session salt, and `info`.

Sorting makes both parties derive the same key. It does not bind a username or
prove ownership of an identity; the surrounding protocol must authenticate keys
and identity/session metadata. Use distinct agreed context bytes for each
direction and purpose; do not assume changing the order of supplied keys changes
the output. Generate fresh salt per session. Salt/context are public and must
be transported consistently by the surrounding authenticated protocol.

## Encryption envelope

Use a 32-byte AES key with Go's `cipher.NewGCMWithRandomNonce`. `Seal` generates
a random 12-byte nonce and prepends it to the output. The complete binary form:

`nonce[12] || ciphertext[len(plaintext)] || authentication_tag[16]`

HTTP returns this as a hexadecimal `ciphertext` string alongside exact constants
`version: 1` and `algorithm: "AES-256-GCM"`. Decrypt rejects other constants
before attempting authentication. There is no unencrypted fallback or legacy CFB
decoding. Authenticate supplied AAD with AES-GCM and release no plaintext on
failure. Decryption leaves input buffers unchanged.

The application must stop using a key before 2^32 aggregate encryptions, across
all processes and devices. Prefer short sessions and explicit rotation well
before that bound. The service does not keep per-key counters. It also does not
reject replayed valid ciphertext; the application must persist/deduplicate
authenticated message identifiers, including across crashes and restores.

## Trust and deployment

The HTTP service is an authorized endpoint that sees every submitted secret.
It has no key vault, persistent secret storage, session database or HSM. Server
authentication restricts API access; it is not cryptographic peer authentication.

For E2EE, call the core package on clients and keep all private keys, derived keys
and plaintext there. The backend carries only authenticated public handshake
material and ciphertext. Mobile bindings, identity verification, signed prekeys,
ratchets, group rekeying and multi-device state are separate implementation work.

For true one-time-pad support, a future module needs externally provisioned
uniform random pads, authenticated messages and crash-safe, non-reusable pad
allocation. HKDF-derived pseudorandom bytes are not an information-theoretic OTP.
This package advertises `one_time_pad: false` and contains no OTP placeholder
that could silently fall back to another algorithm.

## Primary references

- [Go crypto/ecdh](https://pkg.go.dev/crypto/ecdh)
- [Go crypto/hkdf](https://pkg.go.dev/crypto/hkdf)
- [Go NewGCMWithRandomNonce](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
