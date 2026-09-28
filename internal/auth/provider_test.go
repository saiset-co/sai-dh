package auth

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	saiTypes "github.com/saiset-co/sai-service/types"
	"github.com/valyala/fasthttp"
)

func requestContext(token string) *saiTypes.RequestCtx {
	request := &fasthttp.Request{}
	request.SetRequestURI("http://localhost/api/v1/keys/derive")
	request.Header.SetMethod("POST")
	request.Header.Set("Authorization", "Bearer "+token)
	request.SetBodyString(`{"private_key":"DO-NOT-FORWARD","message":"SECRET"}`)
	ctx := &fasthttp.RequestCtx{}
	ctx.Init(request, &net.TCPAddr{}, nil)
	return &saiTypes.RequestCtx{RequestCtx: ctx}
}

func TestTokenAuthentication(t *testing.T) {
	token := strings.Repeat("s", 64)
	provider, err := New(Options{Mode: "token", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.ApplyToIncomingRequest(requestContext(token)); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []string{"", "wrong", token + "x"} {
		if !errors.Is(provider.ApplyToIncomingRequest(requestContext(wrong)), ErrUnauthorized) {
			t.Fatal("invalid token accepted")
		}
	}
	ctx := requestContext(token)
	ctx.Request.Header.Del("Authorization")
	ctx.Request.Header.Set("Token", token)
	if err := provider.ApplyToIncomingRequest(ctx); err != nil {
		t.Fatal("SAI Token header rejected")
	}
	ctx.Request.Header.Set("Authorization", "Bearer "+token)
	if !errors.Is(provider.ApplyToIncomingRequest(ctx), ErrUnauthorized) {
		t.Fatal("ambiguous auth accepted")
	}
	for _, options := range []Options{{}, {Mode: "none"}, {Mode: "token"}, {Mode: "token", Token: "short"}, {Mode: "sai-auth", AuthURL: "http://example.com", ServiceName: "sai-dh"}} {
		if _, err := New(options); err == nil {
			t.Fatal("unsafe options accepted")
		}
	}
}

func TestSaiAuthDoesNotReceiveSecrets(t *testing.T) {
	requests := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Error(err)
		}
		requests <- data
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true,"user_id":"user-123"}`))
	}))
	defer server.Close()
	provider, err := New(Options{Mode: "sai-auth", AuthURL: server.URL, ServiceName: "sai-dh"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestContext("access-token")
	if err := provider.ApplyToIncomingRequest(ctx); err != nil {
		t.Fatal(err)
	}
	data := <-requests
	if len(data) != 5 || data["microservice"] != "sai-dh" || data["method"] != "POST" || data["path"] != "/api/v1/keys/derive" || data["token"] != "access-token" {
		t.Fatal("unexpected authorization contract")
	}
	params, ok := data["request_params"].(map[string]any)
	if !ok || len(params) != 0 {
		t.Fatal("crypto request parameters leaked to authorization")
	}
	encoded, _ := json.Marshal(data)
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "DO-NOT-FORWARD") {
		t.Fatal("secret leaked")
	}
	if ctx.UserValue("user_id") != "user-123" {
		t.Fatal("missing authenticated user")
	}
}

func TestSaiAuthFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"denied", 200, `{"allowed":false}`, ErrUnauthorized},
		{"scoped parameters", 200, `{"allowed":true,"modified_params":{"owner_id":"x"}}`, ErrUnauthorized},
		{"invalid response", 200, `not-json`, ErrUnavailable},
		{"outage", 503, `down`, ErrUnavailable},
		{"forbidden", 403, `{}`, ErrUnauthorized},
		{"redirect", 302, `{}`, ErrUnavailable},
		{"oversized response", 200, strings.Repeat("x", 17000), ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/redirect-target")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			provider, err := New(Options{Mode: "sai-auth", AuthURL: server.URL, ServiceName: "sai-dh"})
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.ApplyToIncomingRequest(requestContext("token")); !errors.Is(err, tc.want) {
				t.Fatalf("wrong result: %v", err)
			}
		})
	}
}
