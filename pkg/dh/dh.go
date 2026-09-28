// Package dh provides stateless P-256 ECDH, HKDF-SHA256 and AES-256-GCM.
// It has no SAI, HTTP, database or filesystem dependencies. Use this package
// at the endpoint that is allowed to possess the private key and plaintext.
// It is a cryptographic building block, not an authenticated messaging protocol.
package dh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const (
	Suite             = "SAI-DH-P256-HKDF-SHA256-AES256GCM-v1"
	KeySize           = 32
	PublicKeySize     = 65
	SaltSize          = 32
	MaxContextSize    = 1024
	MaxAADSize        = 4096
	MaxMessageSize    = 1 << 20
	EnvelopeVersion   = 1
	EnvelopeAlgorithm = "AES-256-GCM"
	gcmOverhead       = 12 + 16 // random nonce and authentication tag
)

var (
	ErrPrivateKey  = errors.New("invalid P-256 private key: expected 32 bytes and scalar in range")
	ErrPublicKey   = errors.New("invalid P-256 public key: expected a 65-byte uncompressed point")
	ErrSalt        = errors.New("salt must contain exactly 32 bytes")
	ErrContext     = errors.New("context must contain between 1 and 1024 bytes")
	ErrKey         = errors.New("AES-256 key must contain exactly 32 bytes")
	ErrMessageSize = errors.New("message exceeds 1048576 bytes")
	ErrAADSize     = errors.New("associated data exceeds 4096 bytes")
	ErrCiphertext  = errors.New("invalid or unauthenticated ciphertext")
)

// KeyPair contains secret material. Do not log, cache or publish PrivateKey.
// Bytes are fixed-width, including leading zeroes.
type KeyPair struct {
	PrivateKey  []byte
	PublicKey   []byte
	Fingerprint string
}

func GenerateKeyPair() (KeyPair, error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, errors.New("key generation failed")
	}
	public := key.PublicKey().Bytes()
	fingerprint := sha256.Sum256(public)
	return KeyPair{
		PrivateKey:  key.Bytes(),
		PublicKey:   public,
		Fingerprint: hex.EncodeToString(fingerprint[:]),
	}, nil
}

// GenerateSalt returns public, random session material. Generate it once per
// session, then send the same salt and context to both participants.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("salt generation failed")
	}
	return salt, nil
}

// DeriveKey validates both keys and derives a 32-byte key, never returning the
// raw ECDH output. The KDF binds the suite, both public keys (sorted bytewise)
// and caller-supplied context. This does not authenticate the peer: the caller
// must independently verify the public key/fingerprint and session metadata.
// Each direction/purpose should use a distinct context string, agreed by peers.
func DeriveKey(privateKey, peerPublicKey, salt []byte, context string) ([]byte, error) {
	if len(privateKey) != KeySize {
		return nil, ErrPrivateKey
	}
	private, err := ecdh.P256().NewPrivateKey(privateKey)
	if err != nil {
		return nil, ErrPrivateKey
	}
	if len(peerPublicKey) != PublicKeySize {
		return nil, ErrPublicKey
	}
	peer, err := ecdh.P256().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, ErrPublicKey
	}
	if len(salt) != SaltSize {
		return nil, ErrSalt
	}
	if len(context) == 0 || len(context) > MaxContextSize {
		return nil, ErrContext
	}
	secret, err := private.ECDH(peer)
	if err != nil {
		return nil, ErrPublicKey
	}
	defer clear(secret)
	first, second := private.PublicKey().Bytes(), peer.Bytes()
	if bytes.Compare(first, second) > 0 {
		first, second = second, first
	}
	info := make([]byte, 0, len(Suite)+1+2*PublicKeySize+4+len(context))
	info = append(info, Suite...)
	info = append(info, 0)
	info = append(info, first...)
	info = append(info, second...)
	info = binary.BigEndian.AppendUint32(info, uint32(len(context)))
	info = append(info, context...)
	return hkdf.Key(sha256.New, secret, salt, string(info), KeySize)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKey
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// Encrypt returns nonce || ciphertext || tag. The nonce is generated internally
// by Go; the caller cannot provide or accidentally reuse a nonce. Never encrypt
// 2^32 or more messages under one key (count across all devices/processes).
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	if len(plaintext) > MaxMessageSize {
		return nil, ErrMessageSize
	}
	if len(aad) > MaxAADSize {
		return nil, ErrAADSize
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plaintext, aad), nil
}

// Decrypt authenticates before returning plaintext and does not mutate input.
// It does not detect replays: the calling application must track message IDs.
func Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	if len(aad) > MaxAADSize {
		return nil, ErrAADSize
	}
	if len(ciphertext) < gcmOverhead || len(ciphertext) > MaxMessageSize+gcmOverhead {
		return nil, ErrCiphertext
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nil, ciphertext, aad)
	if err != nil {
		return nil, ErrCiphertext
	}
	return plaintext, nil
}
