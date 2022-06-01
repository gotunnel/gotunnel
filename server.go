package gotunnel

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/patrickmn/go-cache"
)

// Server is responsible for proxying public tunnels to the client over a
// tunnel tunnel. It also listens to control messages from the client.
type Server struct {

	//	Contains all tunnels established with multiple clients.
	//	tunnels Connections

	//	In-memory cache for storing active sessions.
	//	Sessions provides multiplexing over one tunnel.
	//	Each session is mapped with a unique identifier.
	sessions *cache.Cache

	//	connCh is used to publish accepted tunnels for tcp tunnels.
	// connCh chan net.Conn

	//	Server Configuration
	config *ServerConfig

	//	Custom Logger
	log *log.Logger

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

	//	Skip verifying TLS certificate for the server.
	//	By default, this will be false.
	//	Disabling certificate verification makes your tunnel vulnerable to man-in-the-middle attacks.
	InsecureSkipVerify bool

	//	Custom Logger.
	//	If not supplied, no logging output will be printed.
	Logger *log.Logger

	//	Callback functions which are called at specific checkpoints.
	//	Each function returns an error.
	Callbacks Callbacks

	//	Expiration time.
	//	This is the max duration for which an individual tunnel and its associated sessions
	//	will be persisted in the cache, if they aren't closed beforehand.
	//
	//	Recommended: Do not specify an expiration time
	//	and let the tunnel be closed by clients only.
	Expiration time.Duration

	// YamuxConfig defines the config which passed to every new yamux.Session. If nil
	// yamux.DefaultConfig() is used.
	YamuxConfig *yamux.Config
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
	//	OnDistunnel func(http.ResponseWriter, *http.Request) error
}

//	Creates a new server, based on the supplied configuration.
//	And starts listening on the new server.
func StartServer(config *ServerConfig) error {

	server := &Server{
		config: config,

		// Create a cache with a default expiration time of 5 minutes, and which
		// purges expired items every 10 minutes
		tunnels:  cache.New(cache.NoExpiration, config.Expiration),
		sessions: cache.New(cache.NoExpiration, config.Expiration),
		log:      &log.Logger{},
	}

	if config.Logger == nil {
		server.log.SetOutput(ioutil.Discard)
	} else {
		server.log = config.Logger
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
		server.log.Printf("Running HTTPS server on %s", server.config.Address)
		return http.ListenAndServeTLS(server.config.Address, config.Certificate, config.Key, server)
	}

	//	Start a normal HTTP server
	server.log.Printf("Running HTTP server on %s", server.config.Address)
	return http.ListenAndServe(server.config.Address, server)
}

// ServeHTTP creates a tunnel between a
// public tunnel and the client tunnel.
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

		// Check for CONNECT method
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
	s.log.Println("Initiating Tunnel Creation")

	// fetch the auth token the client has sent
	token := r.Header.Get(TokenHeader)

	if token == "" {
		return errors.New("token header not found")
	}

	// Check whether a tunnel associated with this token already exists
	if _, exists := s.tunnels.Get(hostname); exists {
		return errors.New("tunnel for this hostname already exists")
	}

	// If the server config has an Authentication Middleware,
	// trigger that function, before proceeding forward
	if s.config.Auth != nil {
		if err := s.config.Auth(r); err != nil {
			return err
		}
	}

	// Hijack the incoming CONNECT request for a new tunnel.
	// This will now allow us to control this tunnel
	// on our own terms, instead of allowing the
	// http.Handler to close it as soon as the request has been completed.
	conn, err := hijack(w)
	if err != nil {
		return err
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 "+TunnelConnected+"\n\n"); err != nil {
		return fmt.Errorf("error writing response: %s", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("error setting tunnel deadline: %s", err)
	}

	session, err := yamux.Server(conn, s.config.YamuxConfig)
	if err != nil {
		return err
	}

	//	Save the session for future use
	s.sessions.Set(token, session, s.config.Expiration)

	//	Accept a new stream from the client.
	stream, err := acceptStream(session)
	if err != nil {
		s.log.Println("failed to accept stream w/ client")
		return err
	}

	// 	Close the stream and delete the session if something goes wrong.
	defer func() {
		if err != nil {
			if stream != nil {
				stream.Close()
			}

			// delete the session
			s.sessions.Delete(token)
		}
	}()

	// Now that you have initiated a session/stream
	// the client will send you a handshake request.
	if err := acceptHandshake(stream); err != nil {
		s.log.Println("failed to accept handshake from client")
		return err
	}

	// Now that we've completed the handshake,
	// the tunnel has been established.

	// Save this tunnel
	tunnel := tunnel{
		dec:   json.NewDecoder(stream),
		enc:   json.NewEncoder(stream),
		conn:  stream,
		token: token,
		host:  r.URL.Hostname(),
	}

	s.tunnels.Set(r.URL.Hostname(), tunnel, s.config.Expiration)

	// Start listening for incoming messages
	// in a separate goroutine.
	go s.listen(&tunnel)

	// Call the OnConnection callback
	if s.config.Callbacks.OnConnection != nil {
		s.config.Callbacks.OnConnection(w, r)
	}

	s.log.Printf("Tunnel established successfully for %s", tunnel.host)
	return nil
}

//	Accepts a handshake request from supplied connection.
func acceptHandshake(conn net.Conn) error {

	buf := make([]byte, len(HandshakeRequest))
	if _, err := conn.Read(buf); err != nil {
		return err
	}

	// Read the handshake request
	if string(buf) != HandshakeRequest {
		return fmt.Errorf("handshake aborted. got: %s", string(buf))
	}

	// Write your response to the handshake request
	_, err := conn.Write([]byte(HandshakeResponse))

	return err
}

//	Responsible for tunnelling all incoming requests,
//	if their hostname, already has a tunnel.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {

	//	Check whether it's a Websocket connection.
	if r.Method == http.MethodGet &&
		headerContains(r.Header["Connection"], "upgrade") &&
		headerContains(r.Header["Upgrade"], "websocket") {

		s.log.Println("handling websocket connection")
		s.handleWSConnection(w, r)
		return
	}

	host := r.URL.Hostname()

	stream, err := s.dial(host, HTTP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//	Close the stream once the request is handled.
	defer stream.Close()

	// Send the request over that session/stream
	if err := r.Write(stream); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

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

func (s *Server) dial(host string, protocol Type) (net.Conn, error) {

	// Get the tunnel associated with that host
	payload, exists := s.tunnels.Get(host)
	if !exists {
		return nil, errors.New("no tunnel exists for this host")
	}

	tunnel := payload.(tunnel)

	// Get the session associated with this token
	fetchedSession, exists := s.sessions.Get(tunnel.token)
	if !exists {
		return nil, errors.New("no session exists with this host")
	}

	session := fetchedSession.(*yamux.Session)

	msg := Protocol{
		Action: RequestClientSession,
		Type:   protocol,
	}

	// ask client to open a session to us, so we can accept it
	if err := tunnel.send(msg); err != nil {
		// we might have several issues here, either the stream is closed, or
		// the session is going be shut down, the underlying tunnel might
		// be broken. In all cases, it's not reliable anymore having a client
		// session.
		tunnel.conn.Close()
		s.tunnels.Delete(host)

		s.log.Println("client did not open a session")
		return nil, err
	}

	//	Accept the incoming stream from client.
	return acceptStream(session)
}

// Permanently listens for incoming messages on the tunnel
func (s *Server) listen(c *tunnel) {
	for {
		var msg map[string]interface{}
		err := c.dec.Decode(&msg)
		if err != nil {

			// Close the tunnel
			c.Close()

			// Delete the tunnel
			s.tunnels.Delete(c.host)

			if err != io.EOF {
				s.log.Printf("decode err: %s", err)
			}
			return
		}

		// right now we don't do anything with the messages, but because the
		// underlying tunnel needs to established, we know when we have
		// distunnel(above), so we can cleanup the tunnel.
		//	s.log.Printf("msg: %s", msg)
	}
}

//	Hijack let's the caller take control of the connection.
func hijack(w http.ResponseWriter) (net.Conn, error) {

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("webserver doesn't support hijacking")
	}

	conn, _, err := hj.Hijack()
	return conn, err
}

func (s *Server) handleWSConnection(w http.ResponseWriter, r *http.Request) {

	// Hijack the incoming request for a new session.
	// This will now allow us to control this tunnel
	// on our own terms, instead of allowing the
	// http.Handler to close it as soon as the request has been completed.
	conn, err := hijack(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Get the host from the request.
	host := r.URL.Hostname()

	//	Start a stream with the client.
	stream, err := s.dial(host, WS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//	Write the websocket upgrade request back to the original request.
	if err := r.Write(stream); err != nil {
		http.Error(w, "unable to write upgrade request: "+err.Error(), http.StatusBadGateway)
		stream.Close()
		return
	}

	//	Read the response.
	resp, err := http.ReadResponse(bufio.NewReader(stream), r)
	if err != nil {
		http.Error(w, "unable to read upgrade response: "+err.Error(), http.StatusBadGateway)
		stream.Close()
		return
	}

	//	Write the upgrade response back to the original connection.
	if err := resp.Write(conn); err != nil {
		http.Error(w, "unable to write upgrade response: "+err.Error(), http.StatusBadGateway)
		stream.Close()
		return
	}

	//	Start proxying the data to and fro, in parallel goroutines.
	copy(conn, stream, &sync.WaitGroup{})

	//	Close both the stream w/ client, and the original session connection,
	//	once you are done proxying.
	stream.Close()
	conn.Close()
}

/*
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the username and password from the request
		// Authorization header. If no Authentication header is present
		// or the header value is invalid, then the 'ok' return value
		// will be false.
		username, password, ok := r.BasicAuth()
		if ok {
			// Calculate SHA-256 hashes for the provided and expected
			// usernames and passwords.
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte("your expected username"))
			expectedPasswordHash := sha256.Sum256([]byte("your expected password"))

			// Use the subtle.ConstantTimeCompare() function to check if
			// the provided username and password hashes equal the
			// expected username and password hashes. ConstantTimeCompare
			// will return 1 if the values are equal, or 0 otherwise.
			// Importantly, we should to do the work to evaluate both the
			// username and password before checking the return values to
			// avoid leaking information.
			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			// If the username and password are correct, then call
			// the next handler in the chain. Make sure to return
			// afterwards, so that none of the code below is run.
			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
		}

		// If the Authentication header is not present, is invalid, or the
		// username or password is wrong, then set a WWW-Authenticate
		// header to inform the client that we expect them to use basic
		// authentication and send a 401 Unauthorized response.
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
*/

/*

func (s *Server) handleTCPConn(conn net.Conn) error {
	ident, ok := s.virtualAddrs.getIdent(conn)
	if !ok {
		return fmt.Errorf("no virtual address available for %s", conn.LocalAddr())
	}

	_, port, err := parseHostPort(conn.LocalAddr().String())
	if err != nil {
		return err
	}

	stream, err := s.dial(ident, proto.TCP, port)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go s.proxy(&wg, conn, stream)
	go s.proxy(&wg, stream, conn)

	wg.Wait()

	return nonil(stream.Close(), conn.Close())
}
*/
