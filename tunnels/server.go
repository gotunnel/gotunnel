package tunnels

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

// Server is responsible for proxying public connections to the client over a
// tunnel connection. It also listens to control messages from the client.
type Server struct {

	// Contains all connections established with multiple clients.
	connections Connections

	// sessions contains a session per host.
	// Sessions provides multiplexing over one connection.
	sessions sessions

	// connCh is used to publish accepted connections for tcp tunnels.
	// connCh chan net.Conn

	// Port on which the server is publicly listening for incoming requests.
	// Example: Port 80 on tunnel.nhost.io.
	Port string

	// httpDirector is provided by ServerConfig, if not nil decorates http requests
	// before forwarding them to client.
	// httpDirector func(*http.Request)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func NewServer(port string) *Server {

	response := &Server{
		Port: port,
		sessions: sessions{
			mapping: make(map[string]*yamux.Session),
		},
	}

	return response
}

// ServeHTTP is a tunnel that creates a tunnel between a
// public connection and the client connection.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// TODO: Add more URL validation checks
	if strings.ToLower(r.Host) == "" {
		http.Error(w, "host is empty", http.StatusBadRequest)
		return
	}

	// TODO: Add authentication from Nhost DB

	switch filepath.Clean(r.URL.Path) {
	case CONNECTION_PATH:

		// check for CONNECT Header
		if r.Method != http.MethodConnect {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		// initialize tunnel creation
		if err := s.tunnelCreationHandler(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	default:
		s.handleHTTP(w, r)
	}
}

func (s *Server) tunnelCreationHandler(w http.ResponseWriter, r *http.Request) error {

	log.Println("Initiating Tunnel Creation")

	// fetch the auth token the client has sent
	token := r.Header.Get(TokenHeader)

	// Check whether a connection associated with this token already exists
	if conn := s.connections.exists(token); conn {
		return errors.New("tunnel for this hostname already exists")
	}

	// Hijack the CONNECT request connection.
	// This will now allow us to control this connection
	// on our own terms, instead of allowing the
	// http.Handler to close it as soon as the request has been completed.
	hj, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("webserver doesn't support hijacking: %T", w)
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("hijack not possible: %s", err)
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 "+TunnelConnected+"\n\n"); err != nil {
		return fmt.Errorf("error writing response: %s", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("error setting connection deadline: %s", err)
	}

	log.Println("Starting new session")
	session, err := yamux.Server(conn, nil)
	if err != nil {
		return err
	}

	// save the session for future use
	s.sessions.add(token, session)

	// open a new stream with client
	var stream net.Conn

	// close and delete the session/stream if something goes wrong
	defer func() {
		if err != nil {
			if stream != nil {
				stream.Close()
			}

			// delete the session
			s.sessions.delete(token)
		}
	}()

	acceptStream := func() error {
		stream, err = session.Accept()
		return err
	}

	// if we don't receive anything from the client, we'll timeout
	select {
	case err := <-async(acceptStream):
		if err != nil {
			return err
		}
	case <-time.After(time.Second * 10):
		return errors.New("timeout getting session")
	}

	// Now that you have initiated a sessio/stream
	// the client will send you a handshake request
	log.Println("Initiating handshake protocol")
	buf := make([]byte, len(HandshakeRequest))
	if _, err := stream.Read(buf); err != nil {
		return err
	}

	// Read the client's handshake request
	if string(buf) != HandshakeRequest {
		return fmt.Errorf("handshake aborted. got: %s", string(buf))
	}

	// Write your response to the client's handshake request
	if _, err := stream.Write([]byte(HandshakeResponse)); err != nil {
		return err
	}

	// Now that we've completed the handshake,
	// the tunnel has been established.

	// Save this connection
	connection := connection{
		dec:   json.NewDecoder(stream),
		enc:   json.NewEncoder(stream),
		conn:  stream,
		token: token,
		host:  r.URL.Hostname(),
		port:  strconv.Itoa(GetPort(5000, 9999)),
	}

	s.connections.Add(connection)

	// Start listening for incoming messages
	// in a separate goroutine
	go s.listen(&connection)

	// TODO: Call the onConnection callback

	//
	// IMPORTANT: If we are ever to build Johan's feature
	// of allowing users to control their local dev environments
	// from console.nhost.io, then this is the place where that magic will happen.
	//

	log.Printf("[server] Tunnel established successfully for host %s", connection.host)
	return nil
}

// Permanently listens for incoming messages on the connection
func (s *Server) listen(c *connection) {
	for {
		var msg map[string]interface{}
		err := c.dec.Decode(&msg)
		if err != nil {

			// Close the connection
			c.Close()

			// Delete the connection
			s.connections.delete(*c)

			if err != io.EOF {
				log.Printf("decode err: %s", err)
			}
			return
		}

		// right now we don't do anything with the messages, but because the
		// underlying connection needs to establihsed, we know when we have
		// disconnection(above), so we can cleanup the connection.
		log.Printf("msg: %s", msg)
	}
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {

	// Get the host to which the request has been sent
	host := r.URL.Hostname()

	stream, err := s.dial(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	defer func() {
		log.Println("Closing stream")
		stream.Close()
	}()

	// Send the request over that session/stream
	log.Println("Session opened by client, writing request to client")
	if err := r.Write(stream); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	log.Println("Waiting for tunnelled response of the request from the client")
	resp, err := http.ReadResponse(bufio.NewReader(stream), r)
	if err != nil {
		http.Error(w, "read from tunnel: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Return the response from the client, on the responsewriter
	log.Println("Response received, writing back to public connection")
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) dial(host string) (net.Conn, error) {

	// Get the connection associated with that host
	conn := s.connections.get(host)

	if conn.conn == nil {
		return nil, errors.New("no tunnel exists for this host")
	}

	// Get the session associated with this token
	session, err := s.sessions.get(conn.token)
	if err != nil {
		return nil, errors.New("no session exists with this host")
	}

	msg := Protocol{
		Action: RequestClientSession,
		Type:   HTTP,
	}

	log.Println("Requesting session from client")

	// ask client to open a session to us, so we can accept it
	if err := conn.send(msg); err != nil {
		// we might have several issues here, either the stream is closed, or
		// the session is going be shut down, the underlying connection might
		// be broken. In all cases, it's not reliable anymore having a client
		// session.
		conn.Close()
		s.connections.delete(*conn)
		return nil, err
	}

	var stream net.Conn
	acceptStream := func() error {
		stream, err = session.Accept()
		return err
	}

	// if we don't receive anything from the client, we'll timeout
	log.Println("Waiting to accept the incomingm session")

	select {
	case err := <-async(acceptStream):
		return stream, err
	case <-time.After(10 * time.Second):
		return nil, errors.New("timeout getting session")
	}
}
