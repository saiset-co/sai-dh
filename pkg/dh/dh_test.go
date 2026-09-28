package dh

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

func fromHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func pair(t *testing.T) KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.PrivateKey) != 32 || len(kp.PublicKey) != 65 || len(kp.Fingerprint) != 64 {
		t.Fatal("unexpected key encoding")
	}
	return kp
}

func TestAgreementAndContextBinding(t *testing.T) {
	a, b := pair(t), pair(t)
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	ka, err := DeriveKey(a.PrivateKey, b.PublicKey, salt, "chat/123/alice-to-bob")
	if err != nil {
		t.Fatal(err)
	}
	kb, err := DeriveKey(b.PrivateKey, a.PublicKey, salt, "chat/123/alice-to-bob")
	if err != nil || !bytes.Equal(ka, kb) || len(ka) != 32 {
		t.Fatal("key agreement failed")
	}
	other, err := DeriveKey(a.PrivateKey, b.PublicKey, salt, "chat/123/bob-to-alice")
	if err != nil || bytes.Equal(ka, other) {
		t.Fatal("context must separate keys")
	}
	salt[0] ^= 1
	other, err = DeriveKey(a.PrivateKey, b.PublicKey, salt, "chat/123/alice-to-bob")
	if err != nil || bytes.Equal(ka, other) {
		t.Fatal("salt must separate sessions")
	}
}

func TestRejectInvalidInputs(t *testing.T) {
	a, b := pair(t), pair(t)
	salt := make([]byte, SaltSize)
	tests := []struct {
		name                  string
		private, public, salt []byte
		context               string
		want                  error
	}{
		{"short private", []byte{1}, b.PublicKey, salt, "test", ErrPrivateKey},
		{"zero scalar", make([]byte, 32), b.PublicKey, salt, "test", ErrPrivateKey},
		{"scalar outside order", bytes.Repeat([]byte{255}, 32), b.PublicKey, salt, "test", ErrPrivateKey},
		{"short public", a.PrivateKey, []byte{4}, salt, "test", ErrPublicKey},
		{"off curve point", a.PrivateKey, append([]byte{4}, make([]byte, 64)...), salt, "test", ErrPublicKey},
		{"missing salt", a.PrivateKey, b.PublicKey, nil, "test", ErrSalt},
		{"missing context", a.PrivateKey, b.PublicKey, salt, "", ErrContext},
		{"oversize context", a.PrivateKey, b.PublicKey, salt, strings.Repeat("x", MaxContextSize+1), ErrContext},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := DeriveKey(tc.private, tc.public, tc.salt, tc.context)
			if !errors.Is(err, tc.want) || key != nil {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestAuthenticatedEncryption(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	aad := []byte("chat/123/message/7")
	for _, plaintext := range [][]byte{nil, []byte("שלום — hello"), {0, 255, 0, 1}, bytes.Repeat([]byte{1}, MaxMessageSize)} {
		ciphertext, err := Encrypt(key, plaintext, aad)
		if err != nil {
			t.Fatal(err)
		}
		original := bytes.Clone(ciphertext)
		decoded, err := Decrypt(key, ciphertext, aad)
		if err != nil || !bytes.Equal(decoded, plaintext) {
			t.Fatal("round trip failed")
		}
		if !bytes.Equal(original, ciphertext) {
			t.Fatal("decryption mutated input")
		}
		second, err := Encrypt(key, plaintext, aad)
		if err != nil || bytes.Equal(second, ciphertext) {
			t.Fatal("nonce was not randomized")
		}
	}
	ciphertext, err := Encrypt(key, []byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	// Every byte of nonce, ciphertext and tag must be authenticated.
	for index := range ciphertext {
		changed := bytes.Clone(ciphertext)
		changed[index] ^= 1
		plaintext, err := Decrypt(key, changed, aad)
		if !errors.Is(err, ErrCiphertext) || plaintext != nil {
			t.Fatal("tampering accepted")
		}
	}
	for _, invalidAAD := range [][]byte{nil, []byte("another chat")} {
		plaintext, err := Decrypt(key, ciphertext, invalidAAD)
		if !errors.Is(err, ErrCiphertext) || plaintext != nil {
			t.Fatal("wrong associated data accepted")
		}
	}
	wrongKey := bytes.Clone(key)
	wrongKey[0] ^= 1
	if plaintext, err := Decrypt(wrongKey, ciphertext, aad); !errors.Is(err, ErrCiphertext) || plaintext != nil {
		t.Fatal("wrong key accepted")
	}
	for n := 0; n < gcmOverhead; n++ {
		if plaintext, err := Decrypt(key, make([]byte, n), nil); !errors.Is(err, ErrCiphertext) || plaintext != nil {
			t.Fatal("truncated envelope accepted")
		}
	}
	if _, err := Encrypt(key[:16], nil, nil); !errors.Is(err, ErrKey) {
		t.Fatal("short AES key accepted")
	}
	if _, err := Encrypt(key, make([]byte, MaxMessageSize+1), nil); !errors.Is(err, ErrMessageSize) {
		t.Fatal("oversized message accepted")
	}
	if _, err := Encrypt(key, nil, make([]byte, MaxAADSize+1)); !errors.Is(err, ErrAADSize) {
		t.Fatal("oversized AAD accepted")
	}
}

func TestIndependentVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name       string `json:"name"`
		PrivateA   string `json:"private_a"`
		PublicA    string `json:"public_a"`
		PrivateB   string `json:"private_b"`
		PublicB    string `json:"public_b"`
		Salt       string `json:"salt"`
		Context    string `json:"context"`
		Key        string `json:"key"`
		AAD        string `json:"aad"`
		Plaintext  string `json:"plaintext_hex"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 2 {
		t.Fatal("missing vectors")
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			key, err := DeriveKey(fromHex(t, vector.PrivateA), fromHex(t, vector.PublicB), fromHex(t, vector.Salt), vector.Context)
			if err != nil || !bytes.Equal(key, fromHex(t, vector.Key)) {
				t.Fatalf("reference KDF mismatch: %v", err)
			}
			reverse, err := DeriveKey(fromHex(t, vector.PrivateB), fromHex(t, vector.PublicA), fromHex(t, vector.Salt), vector.Context)
			if err != nil || !bytes.Equal(key, reverse) {
				t.Fatal("reference agreement mismatch")
			}
			plaintext, err := Decrypt(key, fromHex(t, vector.Ciphertext), []byte(vector.AAD))
			if err != nil || !bytes.Equal(plaintext, fromHex(t, vector.Plaintext)) {
				t.Fatal("reference AES-GCM mismatch")
			}
		})
	}
}

func TestConcurrentUse(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ciphertext, err := Encrypt(key, []byte("parallel"), nil)
			if err != nil {
				t.Error(err)
				return
			}
			plaintext, err := Decrypt(key, ciphertext, nil)
			if err != nil || string(plaintext) != "parallel" {
				t.Error("parallel round trip failed")
			}
		}()
	}
	wg.Wait()
}

func FuzzDeriveKey(f *testing.F) {
	f.Add([]byte{1}, []byte{4}, make([]byte, 32), "test")
	f.Fuzz(func(t *testing.T, private, public, salt []byte, context string) {
		key, err := DeriveKey(private, public, salt, context)
		if err != nil && key != nil {
			t.Fatal("failed derivation returned secret material")
		}
		if err == nil && len(key) != KeySize {
			t.Fatal("incorrect derived-key length")
		}
	})
}

func FuzzDecrypt(f *testing.F) {
	f.Add(make([]byte, 32), []byte("invalid"), []byte("metadata"))
	f.Fuzz(func(t *testing.T, key, ciphertext, aad []byte) {
		plaintext, err := Decrypt(key, ciphertext, aad)
		if err != nil && plaintext != nil {
			t.Fatal("failed authentication returned plaintext")
		}
	})
}
