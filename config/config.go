package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type ServerType string
type HandlerType string

const (
	Socket ServerType = "socket"
	Socks5 ServerType = "socks5"
	Ssl    ServerType = "ssl-socket"
	Https  ServerType = "https"

	Echo HandlerType = "echo"
)

type ServerConfig struct {
	Type        ServerType  `yaml:"type"`
	Enabled     bool        `yaml:"enabled"`
	Host        string      `yaml:"host"`
	Port        int         `yaml:"port"`
	HandlerType HandlerType `yaml:"handler"`

	// Socks5 specific
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Protocol string `yaml:"protocol"`

	// Ssl specific
	Cert          string   `yaml:"certfile"`
	Key           string   `yaml:"keyfile"`
	Ca            string   `yaml:"cafile"`
	MinTlsVersion string   `yaml:"minTlsVersion"`
	MaxTlsVersion string   `yaml:"maxTlsVersion"`
	CipherSuites  []string `yaml:"cipherSuites"`
	CurveTypes    []string `yaml:"curveTypes"`
}

type Config struct {
	Servers []ServerConfig `yaml:"servers"`
}

func (cfg *Config) ReadConfig(configPath *string) {
	if *configPath == "" {
		log.Fatal("No config file specified")
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		log.Fatalf("Config file not found: %s", *configPath)
	}

	yamlFile, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %s, err: %v", *configPath, err)
	}

	err = yaml.Unmarshal(yamlFile, cfg)
	if err != nil {
		log.Fatalf("Failed to unmarshal config file: %s, err: %v", *configPath, err)
	}

	for _, server := range cfg.Servers {
		if !server.Enabled {
			log.Printf("Server is disabled in the config, skipping:  %s\n", server.Type)
			continue
		}
	}
}
