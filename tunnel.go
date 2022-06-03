package gotunnel

import (
	"encoding/json"
	"errors"
	"net"
)

// TunnelState represents client tunnel State to tunnel server.
type TunnelState uint32

// TunnelState enumeration
const (
	Unknown TunnelState = iota
	Connecting
	Connected
	Disconnected // keep it always last

	// ClientIdentifierHeader is header carrying information about tunnel identifier.
	IdentifierHeader = "x-gotunnel-identifier"

	// Connected is message sent by server to client when control connection was established.
	TunnelConnected = "200 gotunnel established"

	CONNECTION_PATH = "/_connectPath"
)

var (

	//	Errors
	ErrTunnelExists   = errors.New("tunnel already exists")
	ErrTunnelNotFound = errors.New("no tunnel exists for this host")
)

//	Primary structure for a client-server tunnel.
type tunnel struct {
	enc *json.Encoder
	dec *json.Decoder

	// Holds the actual tunnel instance.
	conn net.Conn

	// Public subdomain on which tunnel is listening on.
	// Example: wahal.tunnel.wah.al
	host string

	// Port which the tunnel is locally listening on.
	port string

	// Authentication token sent by client to authorize the tunnel.
	token string

	// Records whether the tunnel is already closed or not.
	closed bool

	//	BasicAuth credentials to protect incoming visitor sessions.
	//	credentials Credentials
}

func (t *tunnel) Close() error {

	if t == nil {
		return nil
	}

	t.closed = true

	return t.conn.Close()
}

func (t *tunnel) send(v interface{}) error {

	if t.enc == nil {
		return errors.New("encoder is not initialized")
	}

	if t.closed {
		return errors.New("tunnel is closed")
	}

	return t.enc.Encode(v)
}

func (t *tunnel) recv(v interface{}) error {

	if t.dec == nil {
		return errors.New("decoder is not initialized")
	}

	if t.closed {
		return errors.New("tunnel is closed")
	}

	return t.dec.Decode(v)
}

/*
// Issue every tunnel a reverse proxy
func (c *tunnel) IssueProxy(mux *http.ServeMux) error {

	origin, err := url.Parse(c.host + ":" + c.port)
	if err != nil {
		return err
	}

	proxy := httputil.NewSingleHostReverseProxy(origin)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	return nil
}
*/
