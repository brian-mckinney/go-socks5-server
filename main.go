package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"go-test-servers/certificates"
	"go-test-servers/config"
	"go-test-servers/servers"
)

func main() {
	// Handle SIGINT
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			log.Printf("captured %v, stopping server and exiting..", sig)
			os.Exit(1)
		}
	}()

	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	thisDir := filepath.Dir(ex)
	os.Chdir(thisDir)

	configPath := flag.String("config", "config.yaml", "path to the config file")
	generateCertificates := flag.String("make_cert", "", "generate certificate [RSA, ECDSA]")

	flag.Parse()

	if *generateCertificates != "" {
		keyType, err := certificates.ParseKeyType(*generateCertificates)
		if err != nil {
			log.Fatalf("Invalid certificate type: %v", err)
		}
		err = certificates.GenerateCertificates(keyType, 0, nil, nil)
		if err != nil {
			log.Fatalf("Error generating certificates: %v", err)
		}
		log.Printf("Certificates generated successfully")
		os.Exit(0)
	}

	serverConfig := config.Config{}
	serverConfig.ReadConfig(configPath)

	// Start the servers
	if len(serverConfig.Servers) == 0 {
		log.Println("No servers defined in the config")
		os.Exit(1)
	}

	for _, server := range serverConfig.Servers {
		if !server.Enabled {
			log.Printf("Server is disabled in the config, skipping:  %s\n", server.Type)
			continue
		}

		servers.StartServer(server)
	}

	//wait forever
	log.Println("Waiting, press Ctrl+C to exit")
	select {}
}
