// This example keeps all private keys and plaintext in the local process.
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/saiset-co/sai-dh/pkg/dh"
)

func main() {
	alice, err := dh.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	bob, err := dh.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	salt, err := dh.GenerateSalt()
	if err != nil {
		log.Fatal(err)
	}
	// In a real application verify the peer fingerprint over an authenticated
	// channel. Use fresh ephemeral pairs per session for forward secrecy.
	context := "example/session-1/alice-to-bob"
	aliceKey, err := dh.DeriveKey(alice.PrivateKey, bob.PublicKey, salt, context)
	if err != nil {
		log.Fatal(err)
	}
	bobKey, err := dh.DeriveKey(bob.PrivateKey, alice.PublicKey, salt, context)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(aliceKey, bobKey) {
		log.Fatal("key agreement failed")
	}
	aad := []byte("session-1/message-1")
	ciphertext, err := dh.Encrypt(aliceKey, []byte("Hello from Alice"), aad)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := dh.Decrypt(bobKey, ciphertext, aad)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Key agreement and authenticated decryption succeeded.")
	fmt.Println(string(plaintext))
	clear(alice.PrivateKey)
	clear(bob.PrivateKey)
	clear(aliceKey)
	clear(bobKey)
	clear(plaintext)
}
