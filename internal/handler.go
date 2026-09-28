package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/saiset-co/sai-dh/internal/auth"
	"github.com/saiset-co/sai-dh/pkg/dh"
	"github.com/saiset-co/sai-dh/types"
	saiTypes "github.com/saiset-co/sai-service/types"
)

// The HTTP/JSON limit is independent of the decoded plaintext limit. Highly
// escaped strings must also fit this bound (SAI/fasthttp defaults to 4 MiB).
const MaxRequestBytes = 4 << 20

type Handler struct {
	service  *Service
	provider saiTypes.AuthProvider
}

func NewHandler(service *Service, provider saiTypes.AuthProvider) (*Handler, error) {
	if service == nil || provider == nil {
		return nil, errors.New("service and auth provider are required")
	}
	return &Handler{service: service, provider: provider}, nil
}

func noStore(ctx *saiTypes.RequestCtx) {
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Response.Header.Set("Pragma", "no-cache")
	ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(ctx *saiTypes.RequestCtx, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		data = []byte(`{"error":"internal_error","message":"operation failed"}`)
	}
	noStore(ctx)
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json; charset=utf-8")
	ctx.SetBody(data)
	clear(data)
}

func fail(ctx *saiTypes.RequestCtx, status int, code, message string) {
	writeJSON(ctx, status, types.ErrorResponse{Error: code, Message: message})
}

// Protect enforces authentication even if the framework's middleware manager
// is disabled or fails to initialize. Sensitive routes skip body/header logging,
// caching, compression and duplicate framework authentication in RegisterRoutes.
func (h *Handler) Protect(next saiTypes.FastHTTPHandler) saiTypes.FastHTTPHandler {
	return func(ctx *saiTypes.RequestCtx) {
		noStore(ctx)
		defer func() {
			// Clear a reusable request buffer. Go strings and response buffers may
			// still contain copies: this is not a secure-memory/zeroization guarantee.
			clear(ctx.PostBody())
			if recover() != nil {
				fail(ctx, 500, "internal_error", "operation failed")
			}
		}()
		if len(ctx.Request.URI().QueryString()) != 0 {
			fail(ctx, 400, "invalid_request", "query parameters are not accepted")
			return
		}
		if len(ctx.PostBody()) > MaxRequestBytes {
			fail(ctx, 413, "request_too_large", "request body is too large")
			return
		}
		if err := h.provider.ApplyToIncomingRequest(ctx); err != nil {
			if errors.Is(err, auth.ErrUnavailable) {
				fail(ctx, 503, "auth_unavailable", "authorization service unavailable")
			} else {
				ctx.Response.Header.Set("WWW-Authenticate", "Bearer")
				fail(ctx, 401, "unauthorized", "authentication required")
			}
			return
		}
		next(ctx)
	}
}

func readJSON(ctx *saiTypes.RequestCtx, target any) bool {
	mediaType, _, err := mime.ParseMediaType(string(ctx.Request.Header.ContentType()))
	if err != nil || mediaType != "application/json" {
		fail(ctx, 415, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	body := bytes.TrimSpace(ctx.PostBody())
	if len(body) == 0 || body[0] != '{' || !utf8.Valid(body) {
		fail(ctx, 400, "invalid_json", "body must be a JSON object")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		fail(ctx, 400, "invalid_json", "invalid JSON object or unknown field")
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		fail(ctx, 400, "invalid_json", "body must contain exactly one JSON object")
		return false
	}
	return true
}

func (h *Handler) GenerateKeyPair(ctx *saiTypes.RequestCtx) {
	var request types.EmptyRequest
	if !readJSON(ctx, &request) {
		return
	}
	response, err := h.service.GenerateKeyPair()
	if err != nil {
		fail(ctx, 500, "internal_error", "key generation failed")
		return
	}
	writeJSON(ctx, 200, response)
}

func (h *Handler) GenerateSalt(ctx *saiTypes.RequestCtx) {
	var request types.EmptyRequest
	if !readJSON(ctx, &request) {
		return
	}
	response, err := h.service.GenerateSalt()
	if err != nil {
		fail(ctx, 500, "internal_error", "salt generation failed")
		return
	}
	writeJSON(ctx, 200, response)
}

func (h *Handler) Derive(ctx *saiTypes.RequestCtx) {
	var request types.DeriveRequest
	if !readJSON(ctx, &request) {
		return
	}
	response, err := h.service.Derive(request)
	if err != nil {
		fail(ctx, 400, "invalid_request", err.Error())
		return
	}
	writeJSON(ctx, 200, response)
}

func (h *Handler) Encrypt(ctx *saiTypes.RequestCtx) {
	var request types.EncryptRequest
	if !readJSON(ctx, &request) {
		return
	}
	response, err := h.service.Encrypt(request)
	if err != nil {
		fail(ctx, 400, "invalid_request", err.Error())
		return
	}
	writeJSON(ctx, 200, response)
}

func (h *Handler) Decrypt(ctx *saiTypes.RequestCtx) {
	var request types.DecryptRequest
	if !readJSON(ctx, &request) {
		return
	}
	response, err := h.service.Decrypt(request)
	if err != nil {
		fail(ctx, 400, "decryption_failed", "invalid key, envelope or associated data")
		return
	}
	writeJSON(ctx, 200, response)
}

func (h *Handler) Capabilities(ctx *saiTypes.RequestCtx) {
	writeJSON(ctx, 200, types.CapabilitiesResponse{
		Service: "sai-dh", Suite: dh.Suite, Stateless: true,
		MaxMessageBytes:    dh.MaxMessageSize,
		PeerAuthentication: false, ReplayProtection: false, OneTimePad: false,
	})
}

func RegisterRoutes(router saiTypes.HTTPRouter, h *Handler) {
	api := router.Group("/api/v1").WithoutMiddlewares("auth", "logging", "cache", "compression")
	api.GET("/capabilities", h.Protect(h.Capabilities)).
		WithDoc("Capabilities", "Supported suite and protocol limitations", "crypto", nil, &types.CapabilitiesResponse{})
	api.POST("/keys/generate", h.Protect(h.GenerateKeyPair)).
		WithDoc("Generate key pair", "Returns a private key; call only on a trusted endpoint", "keys", &types.EmptyRequest{}, &types.KeyPairResponse{})
	api.POST("/salts/generate", h.Protect(h.GenerateSalt)).
		WithDoc("Generate session salt", "Generate once and share with the other participant", "keys", &types.EmptyRequest{}, &types.SaltResponse{})
	api.POST("/keys/derive", h.Protect(h.Derive)).
		WithDoc("Derive encryption key", "P-256 ECDH followed by context-bound HKDF-SHA256", "keys", &types.DeriveRequest{}, &types.DeriveResponse{})
	api.POST("/encrypt", h.Protect(h.Encrypt)).
		WithDoc("Encrypt", "AES-256-GCM with an internally generated nonce", "crypto", &types.EncryptRequest{}, &types.Envelope{})
	api.POST("/decrypt", h.Protect(h.Decrypt)).
		WithDoc("Decrypt", "Authenticate the envelope before returning plaintext", "crypto", &types.DecryptRequest{}, &types.DecryptResponse{})
}
