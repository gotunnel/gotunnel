package gotunnel

// Type represents tunneled connection type.
type Type int

// Type represents type of control message.
type Action int

const (
	HTTP Type = iota + 1
	TCP
	WS
	SSH

	Requested Type = iota
	Accepted
	Established

	RequestClientSession Action = iota + 1
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
