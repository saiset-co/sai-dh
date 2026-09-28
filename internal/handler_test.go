package internal

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/saiset-co/sai-dh/internal/auth"
	"github.com/saiset-co/sai-dh/types"
	saiTypes "github.com/saiset-co/sai-service/types"
	"github.com/valyala/fasthttp"
)

const testToken = "test-only-0123456789abcdef0123456789abcdef"

func testHandler(t *testing.T) *Handler {
	t.Helper()
	provider, err := auth.New(auth.Options{Mode: "token", Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewService(), provider)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func invoke(handler saiTypes.FastHTTPHandler, body, token, contentType string) *saiTypes.RequestCtx {
	request := &fasthttp.Request{}
	request.SetRequestURI("http://localhost/api/v1/test")
	request.Header.SetMethod("POST")
	request.Header.SetContentType(contentType)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.SetBodyString(body)
	ctx := &fasthttp.RequestCtx{}
	ctx.Init(request, &net.TCPAddr{}, nil)
	wrapped := &saiTypes.RequestCtx{RequestCtx: ctx}
	handler(wrapped)
	return wrapped
}

func TestGuardAndJSONValidation(t *testing.T) {
	h := testHandler(t)
	for _, tc := range []struct {
		name, body, token, contentType string
		status                         int
	}{
		{"missing auth", `{}`, "", "application/json", 401},
		{"bad auth", `{}`, "bad", "application/json", 401},
		{"valid", `{}`, testToken, "application/json", 200},
		{"wrong media type", `{}`, testToken, "text/plain", 415},
		{"null", `null`, testToken, "application/json", 400},
		{"array", `[]`, testToken, "application/json", 400},
		{"trailing object", `{} {}`, testToken, "application/json", 400},
		{"unknown field", `{"private_key":"DO-NOT-ECHO"}`, testToken, "application/json", 400},
		{"large body", strings.Repeat("x", MaxRequestBytes+1), testToken, "application/json", 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := invoke(h.Protect(h.GenerateKeyPair), tc.body, tc.token, tc.contentType)
			if ctx.Response.StatusCode() != tc.status {
				t.Fatalf("status %d, wanted %d", ctx.Response.StatusCode(), tc.status)
			}
			if string(ctx.Response.Header.Peek("Cache-Control")) != "no-store" {
				t.Fatal("missing no-store")
			}
			if strings.Contains(string(ctx.Response.Body()), "DO-NOT-ECHO") {
				t.Fatal("error echoed input")
			}
		})
	}
}

func TestHandlerEncryptionAndTamper(t *testing.T) {
	h := testHandler(t)
	key := strings.Repeat("01", 32)
	body, _ := json.Marshal(types.EncryptRequest{Key: key, Message: "hello", AAD: "message/1"})
	ctx := invoke(h.Protect(h.Encrypt), string(body), testToken, "application/json")
	if ctx.Response.StatusCode() != 200 {
		t.Fatal("encrypt failed")
	}
	var envelope types.Envelope
	if err := json.Unmarshal(ctx.Response.Body(), &envelope); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		aad    string
		status int
	}{{"message/1", 200}, {"message/2", 400}} {
		body, _ = json.Marshal(types.DecryptRequest{Key: key, Envelope: envelope, AAD: tc.aad})
		ctx = invoke(h.Protect(h.Decrypt), string(body), testToken, "application/json")
		if ctx.Response.StatusCode() != tc.status {
			t.Fatal("decryption authentication failure")
		}
	}
	envelope.Version = 0
	body, _ = json.Marshal(types.DecryptRequest{Key: key, Envelope: envelope, AAD: "message/1"})
	if ctx = invoke(h.Protect(h.Decrypt), string(body), testToken, "application/json"); ctx.Response.StatusCode() != 400 {
		t.Fatal("version downgrade accepted")
	}
}

func TestGuardRecoversWithoutSecretDisclosure(t *testing.T) {
	h := testHandler(t)
	ctx := invoke(h.Protect(func(*saiTypes.RequestCtx) { panic("SENSITIVE-PANIC-VALUE") }), `{}`, testToken, "application/json")
	if ctx.Response.StatusCode() != 500 || strings.Contains(string(ctx.Response.Body()), "SENSITIVE") {
		t.Fatal("unsafe panic recovery")
	}
}
