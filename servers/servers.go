package servers

import (
	"fmt"
	"go-test-servers/config"
	"log"
)

func StartServer(cfg config.ServerConfig) error {
	defer func() {
		// ensure a new line, even if we return early from error
		fmt.Println()
	}()

	status := make(chan bool)

	fmt.Println()
	log.Printf("Attempting to start %s server\n", cfg.Type)

	switch cfg.Type {
	case config.Socket:
		go RunTcpSocketServer(cfg, status)
	case config.Socks5:
		go RunSocksServer(cfg, status)
	case config.Ssl, config.Https:
		go RunTlsServer(cfg, status)
	default:
		log.Printf("Unknown server type: %s\n", cfg.Type)
		return fmt.Errorf("unknown server type: %s", cfg.Type)

	}

	if <-status {
		log.Printf("Started %s server\n", cfg.Type)
	} else {
		log.Printf("Failed to start %s server\n", cfg.Type)
		return fmt.Errorf("failed to start %s server", cfg.Type)
	}

	return nil
}
