package tunnels

// Type represents tunneled connection type.
type Type int

const (
	HTTP Type = iota + 1
	TCP
	WS
	SSH

	Requested Type = iota
	Accepted
	Established
)

// Custom gotunnel protocol
type Protocol struct {
	Type   Type
	Action Action
}
