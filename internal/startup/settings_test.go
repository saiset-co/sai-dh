package startup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saiset-co/sai-service/config"
	"gopkg.in/yaml.v3"
)

func cleanEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"SAI_DH_HOST": "127.0.0.1", "SAI_DH_PORT": "8083",
		"SAI_DH_AUTH_ALLOW_HTTP": "false", "SAI_DH_AUTH_TIMEOUT": "3s",
		"SAI_DH_AUTH_MODE": "token", "SAI_DH_TOKEN": strings.Repeat("t", 64),
		"SAI_DH_TOKEN_FILE": "", "SAI_DH_AUTH_URL": "",
	} {
		t.Setenv(key, value)
	}
}

func TestEnvironmentAndTokenFile(t *testing.T) {
	cleanEnv(t)
	settings, err := Load()
	if err != nil || settings.Port != 8083 || settings.Auth.Mode != "token" {
		t.Fatalf("load failed: %v", err)
	}
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(strings.Repeat("x", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAI_DH_TOKEN_FILE", file)
	if _, err := Load(); err == nil {
		t.Fatal("ambiguous token sources accepted")
	}
	t.Setenv("SAI_DH_TOKEN", "")
	settings, err = Load()
	if err != nil || settings.Auth.Token != strings.Repeat("x", 64) {
		t.Fatal("token file failed")
	}
	t.Setenv("SAI_DH_PORT", "0")
	if _, err := Load(); err == nil {
		t.Fatal("invalid port accepted")
	}
}

func TestProvidedFrameworkConfiguration(t *testing.T) {
	loader, err := config.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	framework := loader.Defaults()
	data, err := os.ReadFile("../../config.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, framework); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFramework(framework); err != nil {
		t.Fatal(err)
	}
	framework.Middlewares.Logging.Enabled = true
	if err := ValidateFramework(framework); err == nil {
		t.Fatal("unsafe framework logging accepted")
	}
	framework.Middlewares.Logging.Enabled = false
	framework.Database.Enabled = true
	if err := ValidateFramework(framework); err == nil {
		t.Fatal("persistent database accepted")
	}
}
