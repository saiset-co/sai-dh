package types

type EmptyRequest struct{}

type KeyPairResponse struct {
	Suite       string `json:"suite"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

type SaltResponse struct {
	Salt string `json:"salt"`
}

type DeriveRequest struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Salt       string `json:"salt"`
	Context    string `json:"context"`
}

type DeriveResponse struct {
	Suite string `json:"suite"`
	Key   string `json:"key"`
}

type EncryptRequest struct {
	Key     string `json:"key"`
	Message string `json:"message"`
	AAD     string `json:"aad,omitempty"`
}

type Envelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Ciphertext string `json:"ciphertext"`
}

type DecryptRequest struct {
	Key      string   `json:"key"`
	Envelope Envelope `json:"envelope"`
	AAD      string   `json:"aad,omitempty"`
}

type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type CapabilitiesResponse struct {
	Service            string `json:"service"`
	Suite              string `json:"suite"`
	Stateless          bool   `json:"stateless"`
	MaxMessageBytes    int    `json:"max_message_bytes"`
	PeerAuthentication bool   `json:"peer_authentication"`
	ReplayProtection   bool   `json:"replay_protection"`
	OneTimePad         bool   `json:"one_time_pad"`
}
