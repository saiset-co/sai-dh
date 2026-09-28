package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/saiset-co/sai-dh/internal"
	"github.com/saiset-co/sai-dh/internal/auth"
	"github.com/saiset-co/sai-dh/internal/startup"
	"github.com/saiset-co/sai-service/sai"
	"github.com/saiset-co/sai-service/service"
)

func main() {
	configFile := flag.String("config", "config.yml", "SAI framework configuration file")
	check := flag.Bool("healthcheck", false, "check the local service and exit")
	flag.Parse()
	if *check {
		if err := healthcheck(); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	if err := run(*configFile); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(configFile string) error {
	settings, err := startup.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := service.NewService(ctx, configFile)
	if err != nil {
		return fmt.Errorf("initialize SAI service: %w", err)
	}
	config := sai.Config().GetConfig()
	if err := startup.ValidateFramework(config); err != nil {
		return err
	}
	// The HTTP server keeps a pointer to this framework configuration. Override
	// bind settings before Start; tokens never enter YAML or SAI config objects.
	config.Server.HTTP.Host = settings.Host
	config.Server.HTTP.Port = settings.Port
	settings.Auth.ServiceName = config.Name
	provider, err := auth.New(settings.Auth)
	if err != nil {
		return err
	}
	if err := sai.RegisterAuthProvider(auth.ProviderName, provider); err != nil {
		return err
	}
	handler, err := internal.NewHandler(internal.NewService(), provider)
	if err != nil {
		return err
	}
	internal.RegisterRoutes(sai.Router(), handler)
	return srv.Start()
}

func healthcheck() error {
	port := os.Getenv("SAI_DH_PORT")
	if port == "" {
		port = "8083"
	}
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("invalid healthcheck port")
	}
	host := os.Getenv("SAI_DH_HOST")
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort(host, port) + "/health")
	if err != nil {
		return fmt.Errorf("local healthcheck failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("service is unhealthy")
	}
	return nil
}
