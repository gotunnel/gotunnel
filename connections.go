package tunnels

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
)

// Contains the client-server connections
type Connections struct {
	sync.Mutex
	list []connection
}

type connection struct {
	enc *json.Encoder
	dec *json.Decoder

	// Holds the actuall connection instance.
	conn net.Conn

	// Public subdomain on which tunnel is listening on.
	// Example: wahal.tunnel.wah.al
	host string

	// Port which the connection is locally listening on.
	// On server side, this will be the randomly assigned port
	// on which every tunnel is listening for HTTP requests on.
	// NOT port 80 on which the server is fundamentally listening
	// for all incoming requests.
	port string

	// Authentication token sent by client to authorize the tunnel.
	token string

	// Records whether the connection is already closed or not.
	closed bool
}

func (c *Connections) Add(conn connection) {
	c.Lock()
	c.list = append(c.list, conn)
	c.Unlock()
}

func (c *Connections) get(host string) *connection {
	c.Lock()
	var response *connection
	for index := 0; index <= len(c.list); index++ {
		if c.list[index].host == host {
			response = &c.list[index]
			break
		}
	}
	c.Unlock()
	return response
}

func (c *Connections) exists(token string) bool {

	c.Lock()
	var response bool
	for index := 0; index <= len(c.list); index++ {
		if c.list[index].token == token {
			response = true
			break
		}
	}
	c.Unlock()
	return response
}

func (c *Connections) delete(conn connection) {

	c.Lock()
	var i int
	for index := 0; index <= len(c.list); index++ {
		if c.list[index] == conn {
			i = index
			break
		}
	}

	// remove the connection from the list
	c.list = append(c.list[:i], c.list[i+1:]...)
	c.Unlock()
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
