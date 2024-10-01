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

	"github.com/cowsecurity/custom-rce-agent"
	pb "github.com/cowsecurity/custom-rce-agent/pb"
)

var (
	flagTLSCert         string
	flagTLSKey          string
	flagTLSCA           string
	flagAddr            string
)

func init() {
	flag.StringVar(&flagTLSCert, "tls-cert", "", "TLS certificate file")
	flag.StringVar(&flagTLSKey, "tls-key", "", "TLS key file")
	flag.StringVar(&flagTLSCA, "tls-ca", "", "TLS certificate authority")
	flag.StringVar(&flagAddr, "addr", "127.0.0.1:5501", "Address and port to listen on")
}

func parseChainedCommand(fullCmd string) [][]string {
	pipedCmds := strings.Split(fullCmd, ";;;")
	parsedCmds := make([][]string, len(pipedCmds))

	for i, cmd := range pipedCmds {
		parts := strings.Fields(strings.TrimSpace(cmd))
		if len(parts) > 0 {
			parsedCmds[i] = parts
		}
	}

	return parsedCmds
}

func main() {
	flag.Parse()

	var tlsConfig *tls.Config
	var err error

	if !flagDisableSecurity {
		tlsFiles := rce.TLSFiles{
			CACert: flagTLSCA,
			Cert:   flagTLSCert,
			Key:    flagTLSKey,
		}
		tlsConfig, err = tlsFiles.TLSConfig()
		if err != nil {
			log.Fatal(err)
		}
	}

	interceptor := func(c *pb.Command) (*pb.Command, error) {
		fullCmd := c.Name
		if len(c.Arguments) > 0 {
			fullCmd += " " + strings.Join(c.Arguments, " ")
		}

		chainedCmds := parseChainedCommand(fullCmd)

		reconstructedCmd := ""
		for i, cmd := range chainedCmds {
			reconstructedCmd += strings.Join(cmd, " ")
			if i < len(chainedCmds)-1 {
				reconstructedCmd += " && "
			}
		}

		return &pb.Command{
			Name:      "bash",
			Arguments: []string{"-c", reconstructedCmd},
		}, nil
	}

	srv := rce.NewServerWithConfig(rce.ServerConfig{
		Addr:            flagAddr,
		TLS:             tlsConfig,
		AllowAnyCommand: true,
		DisableSecurity: true,
		Interceptor:     interceptor,
	})

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
