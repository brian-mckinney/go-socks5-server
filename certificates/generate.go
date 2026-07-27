package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// KeyType represents the type of key to generate (ECDSA or RSA).
type KeyType int

const (
	ECDSA KeyType = iota
	RSA
)

func ParseKeyType(keyType string) (KeyType, error) {
	switch keyType {
	case "RSA":
		return RSA, nil
	case "ECDSA":
		return ECDSA, nil
	default:
		return ECDSA, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func GenerateCertificates(keyType KeyType, expireAfter time.Duration, dnsNames, ipAddresses []string) error {
	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}
	if len(ipAddresses) == 0 {
		ipAddresses = []string{"127.0.0.1", "::1"}
	}
	if expireAfter == 0 {
		expireAfter = 365 * 24 * time.Hour
	}

	caCertPath := "ca.pem"
	caKeyPath := "ca-key.pem"
	serverCertPath := "server.pem"
	serverKeyPath := "server-key.pem"
	clientCertPath := "client.pem"
	clientKeyPath := "client-key.pem"
	serverChainPath := "server-chain.pem"
	clientChainPath := "client-chain.pem"

	paths := []string{caCertPath, caKeyPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath, serverChainPath, clientChainPath}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete file %s: %v", path, err)
		}
	}

	caCert, caKey, err := generateCertificate(keyType, []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, expireAfter, true, nil, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to generate CA certificate: %v", err)
	}
	if err := writeCertificateToFile(caCertPath, caKeyPath, caCert, caKey); err != nil {
		return fmt.Errorf("failed to write CA certificate to file: %v", err)
	}

	serverCert, serverKey, err := generateCertificate(keyType, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, expireAfter, false, caCert, caKey, dnsNames, ipAddresses)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %v", err)
	}
	if err := writeCertificateToFile(serverCertPath, serverKeyPath, serverCert, serverKey); err != nil {
		return fmt.Errorf("failed to write server certificate to file: %v", err)
	}

	clientCert, clientKey, err := generateCertificate(keyType, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, expireAfter, false, caCert, caKey, dnsNames, ipAddresses)
	if err != nil {
		return fmt.Errorf("failed to generate client certificate: %v", err)
	}
	if err := writeCertificateToFile(clientCertPath, clientKeyPath, clientCert, clientKey); err != nil {
		return fmt.Errorf("failed to write client certificate to file: %v", err)
	}

	serverPem, err := os.ReadFile(serverCertPath)
	if err != nil {
		return fmt.Errorf("failed to read server.pem: %v", err)
	}
	caPem, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read ca.pem: %v", err)
	}
	err = os.WriteFile(serverChainPath, append(serverPem, caPem...), 0644)
	if err != nil {
		return fmt.Errorf("failed to write server-chain.pem: %v", err)
	}

	clientPem, err := os.ReadFile(clientCertPath)
	if err != nil {
		return fmt.Errorf("failed to read client.pem: %v", err)
	}

	err = os.WriteFile(clientChainPath, append(clientPem, caPem...), 0644)
	if err != nil {
		return fmt.Errorf("failed to write client-chain.pem: %v", err)
	}

	return nil
}

func generateCertificate(keyType KeyType, extKeyUsage []x509.ExtKeyUsage, expireAfter time.Duration, isCA bool, parentCert *x509.Certificate, parentKey interface{}, dnsNames, ipAddresses []string) (*x509.Certificate, interface{}, error) {
	// Generate a private key
	var priv interface{}
	var err error
	switch keyType {
	case ECDSA:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case RSA:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, nil, fmt.Errorf("unsupported key type")
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	ips := make([]net.IP, len(ipAddresses))
	for i, ip := range ipAddresses {
		ips[i] = net.ParseIP(ip)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Country:      []string{"US"},
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expireAfter),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		// If the certificate CN matches the parent openssl will reject it, so choose unique CN for CA
		template.Subject.CommonName = "Test CA Certificate"
	}

	// Use self-signed if no parent is provided
	if parentCert == nil || parentKey == nil {
		parentCert = &template
		parentKey = priv
	}

	// Create the certificate
	var pub interface{}
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	default:
		return nil, nil, fmt.Errorf("unsupported key type")
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, pub, parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, priv, nil
}

func writeCertificateToFile(certPath, keyPath string, cert *x509.Certificate, key interface{}) error {
	// Write the certificate to a file
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return fmt.Errorf("failed to write cert file: %v", err)
	}

	// Write the private key to a file
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyFile.Close()

	var typeName string
	var privBytes []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		privBytes, err = x509.MarshalECPrivateKey(k)
		typeName = "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		privBytes = x509.MarshalPKCS1PrivateKey(k)
		typeName = "RSA PRIVATE KEY"
	default:
		return fmt.Errorf("unsupported key type")
	}

	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: typeName, Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key file: %v", err)
	}

	return nil
}
