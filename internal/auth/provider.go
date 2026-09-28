// Package auth implements SAI's provider interface without sending cryptographic
// request bodies to sai-auth. Authorization is at method/path level only.
package auth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	saiTypes "github.com/saiset-co/sai-service/types"
	"github.com/valyala/fasthttp"
)

const ProviderName = "sai-dh-auth"

var (
	ErrUnauthorized = errors.New("authentication required")
	ErrUnavailable  = errors.New("authorization service unavailable")
)

type Options struct {
	Mode        string
	Token       string
	ServiceName string
	AuthURL     string
	AllowHTTP   bool
	Timeout     time.Duration
}

type Provider struct {
	mode        string
	tokenHash   [32]byte
	serviceName string
	verifyURL   string
	client      *http.Client
}

var _ saiTypes.AuthProvider = (*Provider)(nil)

func New(options Options) (*Provider, error) {
	p := &Provider{mode: options.Mode, serviceName: options.ServiceName}
	switch options.Mode {
	case "token":
		if len(options.Token) < 32 || strings.TrimSpace(options.Token) != options.Token {
			return nil, errors.New("SAI_DH_TOKEN must contain at least 32 characters without surrounding whitespace")
		}
		p.tokenHash = sha256.Sum256([]byte(options.Token))
	case "sai-auth":
		if options.ServiceName == "" {
			return nil, errors.New("service name is required")
		}
		u, err := url.Parse(options.AuthURL)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("SAI_DH_AUTH_URL must be an HTTP(S) URL without credentials, query or fragment")
		}
		ip := net.ParseIP(u.Hostname())
		loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
		if u.Scheme == "http" && !loopback && !options.AllowHTTP {
			return nil, errors.New("sai-auth requires HTTPS; set SAI_DH_AUTH_ALLOW_HTTP=true only on a trusted private network")
		}
		p.verifyURL = strings.TrimRight(options.AuthURL, "/") + "/api/v1/auth/verify"
		if options.Timeout <= 0 {
			options.Timeout = 3 * time.Second
		}
		p.client = &http.Client{
			Timeout:       options.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	default:
		return nil, errors.New("SAI_DH_AUTH_MODE must be token or sai-auth")
	}
	return p, nil
}

func (p *Provider) Type() string { return ProviderName }

func extractToken(ctx *saiTypes.RequestCtx) (string, error) {
	header := string(ctx.Request.Header.Peek("Authorization"))
	legacy := string(ctx.Request.Header.Peek("Token"))
	if header != "" && legacy != "" {
		return "", ErrUnauthorized
	}
	if legacy != "" {
		if len(legacy) > 4096 || strings.TrimSpace(legacy) != legacy {
			return "", ErrUnauthorized
		}
		return legacy, nil
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || (!strings.EqualFold(parts[0], "Bearer") && !strings.EqualFold(parts[0], "Token")) || parts[1] == "" || len(parts[1]) > 4096 || strings.TrimSpace(parts[1]) != parts[1] {
		return "", ErrUnauthorized
	}
	return parts[1], nil
}

func (p *Provider) ApplyToIncomingRequest(ctx *saiTypes.RequestCtx) error {
	token, err := extractToken(ctx)
	if err != nil {
		return err
	}
	if p.mode == "token" {
		incoming := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(incoming[:], p.tokenHash[:]) != 1 {
			return ErrUnauthorized
		}
		return nil
	}
	// Deliberately do not read PostBody(), QueryArgs() or arbitrary headers.
	payload := struct {
		Token         string         `json:"token"`
		Microservice  string         `json:"microservice"`
		Method        string         `json:"method"`
		Path          string         `json:"path"`
		RequestParams map[string]any `json:"request_params"`
	}{token, p.serviceName, string(ctx.Method()), string(ctx.Path()), map[string]any{}}
	data, err := json.Marshal(payload)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(data)
	request, err := http.NewRequest(http.MethodPost, p.verifyURL, bytes.NewReader(data))
	if err != nil {
		return ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return ErrUnauthorized
	}
	if response.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	const maxResponse = 16 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return ErrUnavailable
	}
	var result struct {
		Allowed        bool           `json:"allowed"`
		UserID         string         `json:"user_id"`
		ModifiedParams map[string]any `json:"modified_params"`
	}
	if json.Unmarshal(body, &result) != nil {
		return ErrUnavailable
	}
	// Parameter rewriting/scoping cannot safely be applied to crypto requests.
	// Reject it instead of ignoring an authorization restriction.
	if !result.Allowed || len(result.ModifiedParams) != 0 {
		return ErrUnauthorized
	}
	ctx.SetUserValue("user_id", result.UserID)
	return nil
}

func (p *Provider) ApplyToOutgoingRequest(req *fasthttp.Request, config *saiTypes.ServiceAuthConfig) error {
	if config == nil {
		return ErrUnauthorized
	}
	token, ok := config.Payload["token"].(string)
	if !ok || token == "" || strings.ContainsAny(token, "\r\n") {
		return ErrUnauthorized
	}
	req.Header.Del("Token")
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}
