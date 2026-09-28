package startup

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/saiset-co/sai-dh/internal/auth"
	saiTypes "github.com/saiset-co/sai-service/types"
)

type Settings struct {
	Host string
	Port int
	Auth auth.Options
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func Load() (Settings, error) {
	settings := Settings{Host: env("SAI_DH_HOST", "127.0.0.1")}
	if settings.Host == "" || (net.ParseIP(settings.Host) == nil && settings.Host != "localhost") {
		return Settings{}, errors.New("SAI_DH_HOST must be an IP address or localhost")
	}
	port, err := strconv.Atoi(env("SAI_DH_PORT", "8083"))
	if err != nil || port < 1 || port > 65535 {
		return Settings{}, errors.New("SAI_DH_PORT must be between 1 and 65535")
	}
	settings.Port = port
	allowHTTP, err := strconv.ParseBool(env("SAI_DH_AUTH_ALLOW_HTTP", "false"))
	if err != nil {
		return Settings{}, errors.New("SAI_DH_AUTH_ALLOW_HTTP must be true or false")
	}
	timeout, err := time.ParseDuration(env("SAI_DH_AUTH_TIMEOUT", "3s"))
	if err != nil || timeout <= 0 || timeout > 30*time.Second {
		return Settings{}, errors.New("SAI_DH_AUTH_TIMEOUT must be greater than zero and at most 30s")
	}
	token := os.Getenv("SAI_DH_TOKEN")
	if file := os.Getenv("SAI_DH_TOKEN_FILE"); file != "" {
		if token != "" {
			return Settings{}, errors.New("set only one of SAI_DH_TOKEN and SAI_DH_TOKEN_FILE")
		}
		data, readErr := os.ReadFile(file)
		if readErr != nil {
			return Settings{}, errors.New("cannot read SAI_DH_TOKEN_FILE")
		}
		token = strings.TrimSpace(string(data))
		clear(data)
	}
	settings.Auth = auth.Options{
		Mode: env("SAI_DH_AUTH_MODE", "token"), Token: token,
		AuthURL: os.Getenv("SAI_DH_AUTH_URL"), AllowHTTP: allowHTTP, Timeout: timeout,
	}
	return settings, nil
}

// ValidateFramework rejects settings that could persist secrets or enable
// secret-bearing request logs. HTTP auth itself is enforced inside every route.
func ValidateFramework(config *saiTypes.ServiceConfig) error {
	if config == nil || config.Server == nil || config.Server.HTTP == nil || config.Server.TLS == nil || config.Middlewares == nil || config.Logger == nil || config.Cache == nil || config.Database == nil || config.Actions == nil || config.Health == nil {
		return errors.New("invalid SAI configuration: required sections cannot be null")
	}
	if config.Middlewares.Logging == nil || config.Middlewares.Cache == nil || config.Middlewares.Compression == nil || config.Middlewares.Auth == nil {
		return errors.New("invalid SAI middleware configuration")
	}
	if config.Middlewares.Logging.Enabled || config.Middlewares.Cache.Enabled || config.Middlewares.Compression.Enabled || config.Middlewares.Auth.Enabled {
		return errors.New("framework logging, cache, compression and auth middleware must be disabled; sai-dh authenticates in its route guard")
	}
	if config.Cache.Enabled || config.Database.Enabled || config.Actions.Enabled {
		return errors.New("sai-dh must run without cache, database or action payload publishing")
	}
	if config.Logger.Level == "debug" {
		return errors.New("use info, warn or error logging for sai-dh")
	}
	return nil
}
