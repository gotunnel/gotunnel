package gotunnel

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

// Server is responsible for proxying public connections to the client over a
// tunnel connection. It also listens to control messages from the client.
type Server struct {

	//	Contains all connections established with multiple clients.
	//	connections Connections

	//	In-memory cache for storing active sessions.
	//	Sessions provides multiplexing over one connection.
	//	Each session is mapped with a unique identifier.
	sessions *cache.Cache

	//	connCh is used to publish accepted connections for tcp tunnels.
	// connCh chan net.Conn

	//	Server Configuration
	config *ServerConfig

	//	Timeout for connection requests
	timeout time.Duration

	//	Custom Logger
	log *logrus.Logger

	//	In-memory cache for storing active tunnels.
	//	Each tunnel is mapped with a unique hostname.
	tunnels *cache.Cache
}

// Server config specified by the user.
type ServerConfig struct {

	// if not nil decorates http requests
	// before forwarding them to client.
	Director func(*http.Request)

	//
	// Authentication Middleware For Tunnels
	//
	// A function that you can attach to the server
	// for authenticating every tunnel creation request,
	// before you begin the process of creating the tunnel.

	//	Example: You want to ascertain that the user
	//	sending a new tunnel creation request to your gotunnel server,
	//	actually has a registered account in your service or not,
	//	along with their auth tokens.

	// You can supply your custom authentication function.

	// It takes an HTTP request and returns an error.
	// If the error is nil, then authentication is complete,
	// and server will continue with the tunnel creation procedure.
	// If the error is NOT nil, server will return the error,
	// to the client, without proceeding ahead with hijacking.
	Auth func(*http.Request) error

	//	Address on which the server is publicly listening for incoming requests.
	//	Example: :80.
	//	If a secure scheme (ex. HTTPS) is used,
	//	then it is mandatory to supply certificate and key file.
	Address string

	// TLS Certificate File
	//
	//	If a secure scheme (ex. HTTPS) is used,
	//	then it is mandatory to supply certificate and key file.
	Certificate string

	// Certificate key file
	//
	//	If a secure scheme (ex. HTTPS) is used,
	//	then it is mandatory to supply certificate and key file.
	Key string

	//	Default timeout for connection requests
	Timeout time.Duration

	//	Skip verifying TLS certificate for the server.
	//	By default, this will be false.
	//	Disabling certificate verification makes your connection vulnerable to man-in-the-middle attacks.
	InsecureSkipVerify bool

	//	Custom Logger
	Logger *logrus.Logger

	//	Callback functions which are called at specific checkpoints.
	//	Each function returns an error.
	Callbacks Callbacks

	//	Expiration time.
	//	This is the max duration for which an individual tunnel will be persisted in the cache,
	//	if it is not closed beforehand.
	//
	//	Recommended: Do not specify an expiration time
	//	and let the tunnel be closed by clients only.
	Expiration time.Duration
}

//	Functions to be called after hitting specific checkpoints.
//	Each function takes a response writer and http request.
//	And returns an error.
//
//	Example: Add an `OnConnection` callback function to perform
//	CRUD operations on your database.
type Callbacks struct {

	//	This function is called immediately after a tunnel as been established.
	OnConnection func(http.ResponseWriter, *http.Request) error

	//	This function is called immediately after a tunnel as been dissolved.
	//	OnDisconnection func(http.ResponseWriter, *http.Request) error
}

//	Creates a new server, based on the supplied configuration.
//	And starts listening on the new server.
func StartServer(config *ServerConfig) error {

	//	If no default timeout is specifid,
	//	use the default value.
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}

	server := &Server{
		config:  config,
		timeout: config.Timeout,

		// Create a cache with a default expiration time of 5 minutes, and which
		// purges expired items every 10 minutes
		tunnels:  cache.New(cache.NoExpiration, config.Expiration),
		sessions: cache.New(cache.NoExpiration, config.Expiration),
	}

	if config.Logger != nil {
		server.log = config.Logger
	} else {
		server.log = logrus.New()
	}

	if config.Certificate != "" || config.Key != "" {

		// validate whether the files exist or not
		if !pathExists(config.Certificate) || !pathExists(config.Key) {

			// don't start the server, and return an error
			return errors.New("either certificate or key file not found")
		}

		//	Disabling verification of certificate makes it vulnerable to man-in-the-middle attacks.
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify}

		// if the files exist, start the server
		server.log.Println("Starting HTTPS server")
		return http.ListenAndServeTLS(server.config.Address, config.Certificate, config.Key, server)
	}

	//	Start a normal HTTP server
	server.log.Println("Starting HTTP server")
	return http.ListenAndServe(server.config.Address, server)
}

// ServeHTTP is a tunnel that creates a tunnel between a
// public connection and the client connection.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// If there is an HTTP Director function,
	// usually added to decorate/modify the requests,
	// before tunnelling them through,
	// then activate it.
	if s.config.Director != nil {
		s.config.Director(r)
	}

	// TODO: Add more URL validation checks
	if strings.ToLower(r.Host) == "" {
		http.Error(w, "host is empty", http.StatusBadRequest)
		return
	}

	switch filepath.Clean(r.URL.Path) {
	case CONNECTION_PATH:

		// check for CONNECT method
		if r.Method != http.MethodConnect {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		// begin tunnel creation
		if err := s.tunnelCreationHandler(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		s.handleHTTP(w, r)
	}
}

// Takes a new HTTP CONNECT method request coming from the client,
// to initiate the procedure to creating a new tunnel with that client.
func (s *Server) tunnelCreationHandler(w http.ResponseWriter, r *http.Request) error {

	hostname := r.URL.Hostname()
	s.log.WithField("hostname", hostname).Println("Initiating Tunnel Creation")

	// fetch the auth token the client has sent
	token := r.Header.Get(TokenHeader)

	if token == "" {
		return errors.New("token header not found")
	}

	// Check whether a connection associated with this token already exists
	if _, exists := s.tunnels.Get(hostname); exists {
		return errors.New("tunnel for this hostname already exists")
	}
	/* 	if conn := s.connections.exists(token); conn {
	   		return errors.New("tunnel for this hostname already exists")
	   	}
	*/
	// If the server config has an Authentication Middleware,
	// trigger that function, before proceeding forward
	if s.config.Auth != nil {
		if err := s.config.Auth(r); err != nil {
			return err
		}
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

	s.log.WithField("hostname", hostname).Println("Connection hijacked")
	s.log.WithField("hostname", hostname).Println("Starting new yamux server")
	session, err := yamux.Server(conn, nil)
	if err != nil {
		return err
	}

	//	Save the session for future use
	//	s.sessions.add(token, session)
	s.sessions.Set(token, session, s.config.Expiration)

	// open a new stream with client
	var stream net.Conn

	// close and delete the session/stream if something goes wrong
	defer func() {
		if err != nil {
			if stream != nil {
				stream.Close()
			}

			// delete the session
			s.sessions.Delete(token)
		}
	}()

	// if we don't receive anything from the client, we'll timeout
	acceptStream := func() error {
		stream, err = session.Accept()
		return err
	}
	select {
	case err := <-async(acceptStream):
		if err != nil {
			if session.IsClosed() {
				log.Printf("TCP closed")
				break
			}
			log.Printf("Yamux accept: %s", err)
			return err
		}
	case <-time.After(s.timeout):
		return errors.New("timeout getting session")
	}

	log.Println("accepted stream from client")

	// Now that you have initiated a session/stream
	// the client will send you a handshake request.
	s.log.WithField("hostname", hostname).Println("Initiating handshake protocol")
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
	}

	//	s.connections.Add(connection)
	s.tunnels.Set(r.URL.Hostname(), connection, s.config.Expiration)

	// Start listening for incoming messages
	// in a separate goroutine.
	go s.listen(&connection)

	// Call the OnConnection callback
	if s.config.Callbacks.OnConnection != nil {
		s.config.Callbacks.OnConnection(w, r)
	}

	s.log.WithField("hostname", hostname).Printf("Tunnel established successfully for %s", connection.host)
	return nil
}

//	Responsible for tunnelling all incoming requests,
//	if their hostname, already has a tunnel.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {

	// Get the host to which the request has been sent
	host := r.URL.Hostname()
	stream, err := s.dial(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	defer func() {
		s.log.WithField("hostname", host).Println("Closing stream")
		stream.Close()
	}()

	// Send the request over that session/stream
	s.log.WithField("hostname", host).Println("Session opened by client, writing request to client")
	if err := r.Write(stream); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	s.log.WithField("hostname", host).Println("Waiting for tunnelled response of the request from the client")
	resp, err := http.ReadResponse(bufio.NewReader(stream), r)
	if err != nil {
		http.Error(w, "read from tunnel: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Return the response from the client, on the responsewriter
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) dial(host string) (net.Conn, error) {

	var err error

	// Get the connection associated with that host
	payload, exists := s.tunnels.Get(host)
	if !exists {
		return nil, errors.New("no tunnel exists for this host")
	}

	tunnel := payload.(connection)

	// Get the session associated with this token
	fetchedSession, exists := s.sessions.Get(tunnel.token)
	if !exists {
		return nil, errors.New("no session exists with this host")
	}

	session := fetchedSession.(*yamux.Session)

	msg := Protocol{
		Action: RequestClientSession,
		Type:   HTTP,
	}

	s.log.WithField("hostname", host).Println("Requesting session from client")

	// ask client to open a session to us, so we can accept it
	if err := tunnel.send(msg); err != nil {
		// we might have several issues here, either the stream is closed, or
		// the session is going be shut down, the underlying connection might
		// be broken. In all cases, it's not reliable anymore having a client
		// session.
		tunnel.conn.Close()
		//	s.connections.delete(*conn)
		s.tunnels.Delete(host)
		return nil, err
	}

	//	If we don't receive anything from the client, we will timeout.
	var stream net.Conn
	acceptStream := func() error {
		stream, err = session.Accept()
		return err
	}

	select {
	case err := <-async(acceptStream):
		return stream, err
	case <-time.After(s.timeout):
		return nil, errors.New("timeout getting session")
	}
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
			//	s.connections.delete(*c)
			s.tunnels.Delete(c.host)

			s.log.WithField("hostname", c.host).Println("Deleting connection")

			if err != io.EOF {
				s.log.WithField("hostname", c.host).Printf("decode err: %s", err)
			}
			return
		}

		// right now we don't do anything with the messages, but because the
		// underlying connection needs to established, we know when we have
		// disconnection(above), so we can cleanup the connection.
		//	s.log.WithField("hostname", c.host).Printf("msg: %s", msg)
	}
}
