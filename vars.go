package tunnels

import "time"

// Type represents tunneled connection type.
type Action int

const (
	CONNECTION_PATH = "/_connectPath"

	// ClientIdentifierHeader is header carrying information about tunnel identifier.
	TokenHeader = "x-gotunnel-token"

	// Connected is message sent by server to client when control connection was established.
	TunnelConnected = "200 gotunnel established"

	// HandshakeRequest is hello message sent by client to server.
	HandshakeRequest = "gotunnelHandshakeRequest"
	// HandshakeResponse is response to HandshakeRequest sent by server to client.
	HandshakeResponse = "gotunnelHandshakeOk"

	RequestClientSession Action = iota + 1

	//	Default timeout value used in connection requests.
	DefaultTimeout = 10 * time.Second
)
