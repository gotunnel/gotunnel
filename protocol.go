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

	//	Port of the locally running service.
	//	Example: a file server.
	//
	//	Since, we are following IP based forwarding,
	//	and not port based forwarding, we can skip this.
	//
	//	Server should always get incoming request on port 80.
	//	And the client should manually specify its local service port to tunnel the request to.
	//	Port int
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
