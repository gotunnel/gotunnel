package gotunnel

import (
	"encoding/json"
	"errors"
	"net"
)

//	Primary structure for a client-server tunnel.
type connection struct {
	enc *json.Encoder
	dec *json.Decoder

	// Holds the actual connection instance.
	conn net.Conn

	// Public subdomain on which tunnel is listening on.
	// Example: wahal.tunnel.wah.al
	host string

	// Port which the connection is locally listening on.
	port string

	// Authentication token sent by client to authorize the tunnel.
	token string

	// Records whether the connection is already closed or not.
	closed bool

	//	BasicAuth credentials to protect incoming visitor sessions.
	//	credentials Credentials
}

func (c *connection) Close() error {
	if c == nil {
		return nil
	}

	c.closed = true

	return c.conn.Close()
}

func (c *connection) send(v interface{}) error {
	if c.enc == nil {
		return errors.New("encoder is not initialized")
	}

	if c.closed {
		return errors.New("connection is closed")
	}

	return c.enc.Encode(v)
}

func (c *connection) recv(v interface{}) error {
	if c.dec == nil {
		return errors.New("decoder is not initialized")
	}

	if c.closed {
		return errors.New("connection is closed")
	}

	return c.dec.Decode(v)
}

/*
// Issue every connection a reverse proxy
func (c *connection) IssueProxy(mux *http.ServeMux) error {

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
