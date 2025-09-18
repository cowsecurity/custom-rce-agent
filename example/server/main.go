package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	rce "github.com/cowsecurity/custom-rce-agent"
	pb "github.com/cowsecurity/custom-rce-agent/pb"
)

var (
	flagTLSCert       string
	flagTLSKey        string
	flagTLSCA         string
	flagAddr          string
	flagConfig        string
	flagUseVallumFlow bool
)

func init() {
	flag.StringVar(&flagTLSCert, "tls-cert", "", "TLS certificate file")
	flag.StringVar(&flagTLSKey, "tls-key", "", "TLS key file")
	flag.StringVar(&flagTLSCA, "tls-ca", "", "TLS certificate authority")
	flag.StringVar(&flagAddr, "addr", "127.0.0.1:5501", "Address and port to listen on")
	flag.StringVar(&flagConfig, "config", "/etc/vallumflow/config.json", "VallumFlow configuration file")
	flag.BoolVar(&flagUseVallumFlow, "vallumflow", false, "Use VallumFlow configuration from Lambda")
}

func main() {
	flag.Parse()
	var serverConfig rce.ServerConfig
	var tlsConfig *tls.Config

	interceptor := func(c *pb.Command) (*pb.Command, error) {
		fullCmd := c.Name
		if len(c.Arguments) > 0 {
			fullCmd += " " + strings.Join(c.Arguments, " ")
		}

		return &pb.Command{
			Name:      "bash",
			Arguments: []string{"-c", fullCmd},
		}, nil
	}

	useVallumFlow := false
	if flagUseVallumFlow || (flagTLSCert == "" && flagTLSKey == "" && flagTLSCA == "") {
		if _, err := os.Stat(flagConfig); err == nil {
			log.Printf("Loading VallumFlow configuration from %s", flagConfig)

			cfg, err := rce.LoadConfigFromVallumFlow(flagConfig, nil)
			if err != nil {
				log.Printf("Failed to load VallumFlow config: %v, falling back to legacy mode", err)
			} else {
				serverConfig = rce.ServerConfig{
					Addr:            cfg.Addr,
					TLS:             cfg.TLS,
					OrgID:           cfg.OrgID,
					AllowAnyCommand: true,
					DisableSecurity: cfg.TLS == nil,
					Interceptor:     interceptor,
				}

				if flagAddr != "127.0.0.1:5501" {
					serverConfig.Addr = flagAddr
				}

				log.Printf("Server configured for org: %s with intermediate CA support", cfg.OrgID)
				useVallumFlow = true
			}
		} else {
			log.Printf("VallumFlow config file not found: %s, using legacy mode", flagConfig)
		}
	}

	if !useVallumFlow {
		log.Println("Using legacy TLS configuration")

		if flagTLSCert != "" && flagTLSKey != "" && flagTLSCA != "" {
			tlsFiles := rce.TLSFiles{
				CACert: flagTLSCA,
				Cert:   flagTLSCert,
				Key:    flagTLSKey,
			}
			var err error
			tlsConfig, err = tlsFiles.TLSConfig()
			if err != nil {
				log.Fatalf("Failed to create TLS config: %v", err)
			}
		}

		serverConfig = rce.ServerConfig{
			Addr:            flagAddr,
			TLS:             tlsConfig,
			AllowAnyCommand: true,
			DisableSecurity: tlsConfig == nil,
			Interceptor:     interceptor,
		}
	}

	srv := rce.NewServerWithConfig(serverConfig)

	if err := srv.StartServer(); err != nil {
		log.Fatalf("Error starting server: %s\n", err)
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	fmt.Println("CTRL-C to shut down")
	<-c
	fmt.Println("Shutting down...")
	if err := srv.StopServer(); err != nil {
		log.Printf("Error stopping server: %s\n", err)
	}
}
