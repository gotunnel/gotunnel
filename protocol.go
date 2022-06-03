package gotunnel

// Type represents tunneled connection type.
type Type int

// Type represents type of control message.
type Action int

const (

	//	Protocols
	HTTP Type = iota + 1
	TCP
	WS
	SSH

	//	Actions
	RequestSession Action = iota + 1

	//	Handshakes
	//
	// HandshakeRequest is hello message sent by client to server.
	HandshakeRequest = "gotunnelHandshakeRequest"

	// HandshakeResponse is response to HandshakeRequest sent by server to client.
	HandshakeResponse = "gotunnelHandshakeOk"
)

// Custom gotunnel protocol
type Protocol struct {
	Type   Type
	Action Action
}

//	Matches and returns the protocol type from network string.
func getProtocol(network string) Type {

	switch network {
	case "http", "https":
		return HTTP
	case "tcp":
		return TCP
	case "ws", "wss":
		return WS
	default:
		return SSH
	}
}
