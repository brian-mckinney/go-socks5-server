package config

import (
	"crypto/tls"
	"fmt"
)

// ParseTlsVersion converts a TLS version string to its corresponding constant.
func ParseTlsVersion(version string) (uint16, error) {
	switch version {
	case "TLSv1.0":
		return tls.VersionTLS10, nil
	case "TLSv1.1":
		return tls.VersionTLS11, nil
	case "TLSv1.2":
		return tls.VersionTLS12, nil
	case "TLSv1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}
