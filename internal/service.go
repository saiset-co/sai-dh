package internal

import (
	"encoding/hex"
	"errors"
	"unicode/utf8"

	"github.com/saiset-co/sai-dh/pkg/dh"
	"github.com/saiset-co/sai-dh/types"
)

type Service struct{}

func NewService() *Service { return &Service{} }

func (s *Service) GenerateKeyPair() (types.KeyPairResponse, error) {
	kp, err := dh.GenerateKeyPair()
	if err != nil {
		return types.KeyPairResponse{}, err
	}
	defer clear(kp.PrivateKey)
	return types.KeyPairResponse{
		Suite:       dh.Suite,
		PrivateKey:  hex.EncodeToString(kp.PrivateKey),
		PublicKey:   hex.EncodeToString(kp.PublicKey),
		Fingerprint: kp.Fingerprint,
	}, nil
}

func (s *Service) GenerateSalt() (types.SaltResponse, error) {
	salt, err := dh.GenerateSalt()
	if err != nil {
		return types.SaltResponse{}, err
	}
	return types.SaltResponse{Salt: hex.EncodeToString(salt)}, nil
}

func decodeFixed(value string, size int, invalid error) ([]byte, error) {
	if len(value) != 2*size {
		return nil, invalid
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, invalid
	}
	return decoded, nil
}

func (s *Service) Derive(req types.DeriveRequest) (types.DeriveResponse, error) {
	private, err := decodeFixed(req.PrivateKey, dh.KeySize, dh.ErrPrivateKey)
	if err != nil {
		return types.DeriveResponse{}, err
	}
	defer clear(private)
	public, err := decodeFixed(req.PublicKey, dh.PublicKeySize, dh.ErrPublicKey)
	if err != nil {
		return types.DeriveResponse{}, err
	}
	salt, err := decodeFixed(req.Salt, dh.SaltSize, dh.ErrSalt)
	if err != nil {
		return types.DeriveResponse{}, err
	}
	key, err := dh.DeriveKey(private, public, salt, req.Context)
	if err != nil {
		return types.DeriveResponse{}, err
	}
	defer clear(key)
	return types.DeriveResponse{Suite: dh.Suite, Key: hex.EncodeToString(key)}, nil
}

func (s *Service) Encrypt(req types.EncryptRequest) (types.Envelope, error) {
	key, err := decodeFixed(req.Key, dh.KeySize, dh.ErrKey)
	if err != nil {
		return types.Envelope{}, err
	}
	defer clear(key)
	if !utf8.ValidString(req.Message) || !utf8.ValidString(req.AAD) {
		return types.Envelope{}, errors.New("message and aad must be valid UTF-8")
	}
	plaintext := []byte(req.Message)
	defer clear(plaintext)
	ciphertext, err := dh.Encrypt(key, plaintext, []byte(req.AAD))
	if err != nil {
		return types.Envelope{}, err
	}
	return types.Envelope{
		Version:    dh.EnvelopeVersion,
		Algorithm:  dh.EnvelopeAlgorithm,
		Ciphertext: hex.EncodeToString(ciphertext),
	}, nil
}

func (s *Service) Decrypt(req types.DecryptRequest) (types.DecryptResponse, error) {
	key, err := decodeFixed(req.Key, dh.KeySize, dh.ErrKey)
	if err != nil {
		return types.DecryptResponse{}, err
	}
	defer clear(key)
	if req.Envelope.Version != dh.EnvelopeVersion || req.Envelope.Algorithm != dh.EnvelopeAlgorithm {
		return types.DecryptResponse{}, dh.ErrCiphertext
	}
	if len(req.Envelope.Ciphertext) > 2*(dh.MaxMessageSize+28) {
		return types.DecryptResponse{}, dh.ErrCiphertext
	}
	ciphertext, err := hex.DecodeString(req.Envelope.Ciphertext)
	if err != nil {
		return types.DecryptResponse{}, dh.ErrCiphertext
	}
	plaintext, err := dh.Decrypt(key, ciphertext, []byte(req.AAD))
	if err != nil {
		return types.DecryptResponse{}, err
	}
	defer clear(plaintext)
	if !utf8.Valid(plaintext) {
		return types.DecryptResponse{}, errors.New("plaintext is not valid UTF-8; use the Go package for binary data")
	}
	return types.DecryptResponse{Plaintext: string(plaintext)}, nil
}
