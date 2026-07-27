package handlers

import (
	"crypto/tls"
	"log"
	"net"
)

// RstAfterHandshakeHandler completes the TLS handshake then immediately closes
// the connection with TCP RST (SO_LINGER=0).  Used to regression-test client
// behaviour when a middlebox drops a live TLS connection with RST.
func RstAfterHandshakeHandler(conn net.Conn) {
	defer conn.Close()

	log.Printf("RST-after-handshake connection from %s", conn.RemoteAddr())

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("RST handler: connection is not *tls.Conn, closing normally")
		return
	}

	// Complete the handshake so the client's Connect() returns successfully
	// before we drop the connection.
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("RST handler: handshake failed: %v", err)
		return
	}

	// Set SO_LINGER=0 on the underlying TCP socket so that Close() sends RST
	// rather than the default FIN-based graceful shutdown.
	tcpConn, ok := tlsConn.NetConn().(*net.TCPConn)
	if !ok {
		log.Printf("RST handler: underlying conn is not *net.TCPConn, closing normally")
		return
	}
	if err := tcpConn.SetLinger(0); err != nil {
		log.Printf("RST handler: SetLinger failed: %v", err)
	}

	// defer conn.Close() fires here, sending RST.
}
