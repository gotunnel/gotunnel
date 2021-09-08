package tunnels

// Type represents tunneled connection type.
type Action int

const (
	CONNECTION_PATH = "/_connectPath"

	// ClientIdentifierHeader is header carrying information about tunnel identifier.
	TokenHeader = "X-NHOST-Tunnel-Token"

	// Connected is message sent by server to client when control connection was established.
	TunnelConnected = "200 Nhost Tunnel Established"

	// HandshakeRequest is hello message sent by client to server.
	HandshakeRequest = "nhostHandshakeRequest"
	// HandshakeResponse is response to HandshakeRequest sent by server to client.
	HandshakeResponse = "nhostHandshakeOk"

	RequestClientSession Action = iota + 1
)
