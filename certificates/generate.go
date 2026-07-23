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

// GenerateCrossSignedCertificates generates a cross-signed certificate chain that
// reproduces the Windows AD CS pattern from SDH-801: two root CAs share the same
// Subject DN, and one cross-signs the other. The server chain includes the
// cross-signed cert, which causes OpenSSL's chain builder to explore an
// alternative path and can trigger "certificate chain too long" if the client
// does not handle it correctly.
//
// Files written (same layout as GenerateCertificates so MakeTlsConfig works):
//
//	ca.pem          – OldRoot, the trust anchor loaded by the client
//	ca-key.pem      – OldRoot private key
//	server-key.pem  – server private key
//	server-chain.pem – [server cert | cross-signed NewRoot | OldRoot]
//	client-key.pem  – client private key
//	client-chain.pem – [client cert | OldRoot]
func GenerateCrossSignedCertificates(expireAfter time.Duration, dnsNames, ipAddresses []string) error {
	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}
	if len(ipAddresses) == 0 {
		ipAddresses = []string{"127.0.0.1", "::1"}
	}
	if expireAfter == 0 {
		expireAfter = 365 * 24 * time.Hour
	}

	// Both roots share this Subject DN — the AD CS "same-name" pattern.
	sharedSubject := pkix.Name{
		CommonName:   "Test Root CA",
		Country:      []string{"US"},
		Organization: []string{"Test Organization"},
	}

	newSerial := func() *big.Int {
		n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		return n
	}

	// 1. OldRoot: self-signed, becomes ca.pem (client trust anchor).
	oldRootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate OldRoot key: %v", err)
	}
	oldRootTpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               sharedSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expireAfter),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	oldRootDER, err := x509.CreateCertificate(rand.Reader, oldRootTpl, oldRootTpl, &oldRootKey.PublicKey, oldRootKey)
	if err != nil {
		return fmt.Errorf("create OldRoot: %v", err)
	}
	oldRoot, err := x509.ParseCertificate(oldRootDER)
	if err != nil {
		return fmt.Errorf("parse OldRoot: %v", err)
	}

	// 2. NewRoot: separate key, same Subject DN as OldRoot.
	newRootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate NewRoot key: %v", err)
	}
	newRootTpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               sharedSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expireAfter),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	newRootDER, err := x509.CreateCertificate(rand.Reader, newRootTpl, newRootTpl, &newRootKey.PublicKey, newRootKey)
	if err != nil {
		return fmt.Errorf("create NewRoot: %v", err)
	}
	newRoot, err := x509.ParseCertificate(newRootDER)
	if err != nil {
		return fmt.Errorf("parse NewRoot: %v", err)
	}

	// 3. Cross-signed cert: NewRoot's public key signed by OldRoot.
	//    Subject = NewRoot's DN, Issuer = OldRoot's DN (same string — the ambiguity
	//    that causes OpenSSL's chain builder to explore a deeper alternative path).
	crossTpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               sharedSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expireAfter),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	crossDER, err := x509.CreateCertificate(rand.Reader, crossTpl, oldRoot, &newRootKey.PublicKey, oldRootKey)
	if err != nil {
		return fmt.Errorf("create cross-signed cert: %v", err)
	}
	crossCert, err := x509.ParseCertificate(crossDER)
	if err != nil {
		return fmt.Errorf("parse cross-signed cert: %v", err)
	}

	// 4. Server cert signed by NewRoot.
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate server key: %v", err)
	}
	ips := make([]net.IP, len(ipAddresses))
	for i, ip := range ipAddresses {
		ips[i] = net.ParseIP(ip)
	}
	serverTpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName:   "Test Server",
			Country:      []string{"US"},
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expireAfter),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTpl, newRoot, &serverKey.PublicKey, newRootKey)
	if err != nil {
		return fmt.Errorf("create server cert: %v", err)
	}
	serverCert, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return fmt.Errorf("parse server cert: %v", err)
	}

	// 5. Client cert signed by OldRoot (the server verifies clients against ca.pem = OldRoot).
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate client key: %v", err)
	}
	clientTpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName:   "Test Client",
			Country:      []string{"US"},
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expireAfter),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTpl, oldRoot, &clientKey.PublicKey, oldRootKey)
	if err != nil {
		return fmt.Errorf("create client cert: %v", err)
	}
	clientCert, err := x509.ParseCertificate(clientDER)
	if err != nil {
		return fmt.Errorf("parse client cert: %v", err)
	}

	pemCert := func(cert *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	pemRSAKey := func(key *rsa.PrivateKey) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	}
	write := func(path string, data []byte) error {
		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("write %s: %v", path, err)
		}
		return nil
	}

	if err := write("ca.pem", pemCert(oldRoot)); err != nil {
		return err
	}
	if err := write("ca-key.pem", pemRSAKey(oldRootKey)); err != nil {
		return err
	}
	if err := write("server-key.pem", pemRSAKey(serverKey)); err != nil {
		return err
	}
	// server-chain: server cert → cross-signed NewRoot (signed by OldRoot) → OldRoot.
	// Including the cross-signed cert is what exercises the verify-depth path.
	serverChain := append(pemCert(serverCert), pemCert(crossCert)...)
	serverChain = append(serverChain, pemCert(oldRoot)...)
	if err := write("server-chain.pem", serverChain); err != nil {
		return err
	}
	if err := write("client-key.pem", pemRSAKey(clientKey)); err != nil {
		return err
	}
	clientChain := append(pemCert(clientCert), pemCert(oldRoot)...)
	if err := write("client-chain.pem", clientChain); err != nil {
		return err
	}

	return nil
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
