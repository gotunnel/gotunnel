package tunnels

// Type represents tunneled connection type.
type Type int

const (
	HTTP Type = iota + 1
	TCP
	WS

	Requested Type = iota
	Accepted
	Established
)

// Custom Nhost tunnelling protocol
type Protocol struct {
	Type   Type
	Action Action
}
