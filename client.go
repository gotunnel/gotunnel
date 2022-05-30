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
	"sync"
	"time"

	"net/url"

	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
)

// ClientState represents client connection State to tunnel server.
type ClientState uint32

// ClientState enumeration
const (
	Unknown ClientState = iota
	Started
	Connecting
	Connected
	Disconnected
	Closed // keep it always last
)

type (
	Client struct {

		//	Prased URL of the remote address.
		remote *url.URL

		//	Local port you want to expose to the outside world.
		port string

		//	Unique identifier for storing the tunnel connection.
		identifier string

		//	Client configuration structure.
		config *ClientConfig

		// Read-only Channel on which connection's
		// current state is transmitted to.
		state chan<- *ClientState

		// Contains the established connection state
		// connection connection

		session *yamux.Session

		requestWaitGroup    sync.WaitGroup
		connectionWaitGroup sync.WaitGroup

		//	Custom Logger
		log *logrus.Logger
	}

	//	Client configuration struct
	ClientConfig struct {

		// Hostname on which tunnel is listening for public connections.
		// Example: https://wahal.tunnel.wah.al:443
		Address string

		// Local port you want to expose to the outside world.
		// Bascially, the port on which you want to receive
		// incoming proxy requests through the tunnel.
		Port string

		//	Custom Logger
		Logger *logrus.Logger

		//	Skip verifying TLS certificate for the server.
		//	Value should be the same as what you used in server configuration.
		//	By default, this will be false.
		//	Disabling certificate verification makes your connection vulnerable to man-in-the-middle attacks.
		InsecureSkipVerify bool

		// Authentication token.
		// Will also be used as a unique identifier
		// by the server for storing tunnel connection.
		Token string

		// Read-only Channel on which connection's
		// current state is transmitted to.
		//
		// It's advisable to assign this channel,
		// for better debugging on the vendor's side.
		State chan<- *ClientState
	}
)

//	Create a new client from supplied configuration.
func NewClient(config *ClientConfig) (*Client, error) {

	var err error

	client := &Client{
		port:       config.Port,
		identifier: config.Token,
		config:     config,
	}

	if config.State != nil {
		client.state = config.State
	}

	client.remote, err = url.Parse(config.Address)
	if err != nil {
		return client, err
	}

	//	Initialize a default logger
	if config.Logger != nil {
		client.log = config.Logger
	} else {
		client.log = logrus.New()
	}

	return client, nil
}

// update client's connection states
func (c *Client) changeState(value ClientState) {

	if c.state != nil {
		c.state <- &value
	}
}

func (c *Client) Init() error {

	// Ensure the remote host is reachable
	if err := ping(TCP, c.remote.Host); err != nil {
		return err
	}

	// Ensure the local host is reachable
	if err := ping(TCP, ":"+c.port); err != nil {
		return err
	}

	return nil
}

func (c *Client) Connect() error {

	var err error
	var conn net.Conn

	//	Initialize the client.
	if err := c.Init(); err != nil {
		return err
	}

	// set client State
	c.changeState(Connecting)

	//	Check whether it's a TLS connection.
	switch c.remote.Scheme {
	case "https", "wss":

		//	TLS configuration
		conf := &tls.Config{
			InsecureSkipVerify: c.config.InsecureSkipVerify,
		}

		// Get a TLS connection
		conn, err = tls.Dial(getNetwork(TCP), c.remote.Host, conf)
		if err != nil {
			return err
		}

	default:

		// Get a normal TCP connection
		conn, err = net.Dial(getNetwork(TCP), c.remote.Host)
		if err != nil {
			return err
		}
	}

	remoteURL := fmt.Sprint(c.remote.Scheme, "://", conn.RemoteAddr(), CONNECTION_PATH)
	req, err := http.NewRequest(http.MethodConnect, remoteURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request to %s: %s", remoteURL, err)
	}

	// Set the auth token in gotunnel identification header
	req.Header.Set(TokenHeader, c.identifier)

	// Send the CONNECT Request to request a tunnel from the server
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("writing CONNECT request to %s failed: %s", req.URL, err)
	}

	// Read the server's response on your tunnel creation request
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("reading CONNECT response from %s failed: %s", req.URL, err)
	}

	defer resp.Body.Close()

	// If the response isn't good, inform the client, and cancel this attempt
	if resp.StatusCode != http.StatusOK || resp.Status != TunnelConnected {
		out, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("tunnel server error: status=%d, error=%s", resp.StatusCode, err)
		}

		return fmt.Errorf("tunnel server error: status=%d, body=%s", resp.StatusCode, string(out))
	}

	// wait until previous listening funcs observes disconnection
	c.connectionWaitGroup.Wait()

	// Now that the server has responded well on your request,
	// the server should have ideally hijacked your request connect
	// and might perform a handshake.

	// Setup client side of yamux
	log.Println("Starting new yamux client")
	c.session, err = yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	// open a new stream with server
	var stream net.Conn
	openStream := func() error {

		// this is blocking until server accepts our session
		stream, err = c.session.Open()
		return err
	}

	// if we don't receive anything from the server, we'll timeout
	select {
	case err := <-async(openStream):
		log.Println("opening new stream w/ server")
		if err != nil {
			return fmt.Errorf("session could not be opened: %s", err)
		}
	case <-time.After(DefaultTimeout):
		if stream != nil {
			stream.Close()
		}
		return errors.New("timeout opening session")
	}

	log.Println("sending handshake request to server")
	//	Now that you have successfuly opened a session,
	//	send a handshake request to the server.
	if _, err := stream.Write([]byte(HandshakeRequest)); err != nil {
		return fmt.Errorf("writing handshake request failed: %s", err)
	}

	// Read the server's response to your handshake request
	buf := make([]byte, len(HandshakeResponse))
	if _, err := stream.Read(buf); err != nil {
		return fmt.Errorf("reading handshake response failed: %s", err)
	}

	// If the server has rejected your handshake, then end this mess right here right now
	if string(buf) != HandshakeResponse {
		return fmt.Errorf("invalid handshake response, received: %s", string(buf))
	}

	// Now that we've completed the handshake,
	// the tunnel has been established.
	// Save this connection

	connection := connection{
		dec:   json.NewDecoder(stream),
		enc:   json.NewEncoder(stream),
		conn:  stream,
		host:  c.remote.Host,
		port:  c.port,
		token: c.identifier,
	}

	// c.connection = connection

	// update client State
	c.changeState(Connected)

	// Start listening for incoming messages
	// in a separate goroutine
	return c.listen(&connection)
}

func (c *Client) listen(conn *connection) error {
	c.connectionWaitGroup.Add(1)
	defer c.connectionWaitGroup.Done()

	for {
		var msg Protocol
		if err := conn.dec.Decode(&msg); err != nil {
			c.requestWaitGroup.Wait() // wait until all requests are finished
			c.session.GoAway()
			c.session.Close()

			// update client State
			c.changeState(Disconnected)

			return fmt.Errorf("failed to unmarshal message from server")
		}

		switch msg.Action {
		case RequestClientSession:

			remote, err := c.session.Open()
			if err != nil {
				return err
			}

			go func() {

				// Close the stream with server
				defer remote.Close()

				// Tunnel the request to locally running reverse proxy
				if err := c.tunnel(remote); err != nil {
					c.log.Println(err)
					c.log.Println("failed to proxy data through tunnel")
				}
			}()
		}
	}
}

// Tunnel the request to locally running reverse proxy
func (c *Client) tunnel(remoteConnection net.Conn) error {

	// Dial TCP connection with locally running reverse proxy server
	localConnection, err := net.Dial(getNetwork(TCP), ":"+c.port)
	if err != nil {
		return err
	}
	defer localConnection.Close()

	// proxy the request
	c.requestWaitGroup.Add(2)
	go proxy(localConnection, remoteConnection, &c.requestWaitGroup)
	go proxy(remoteConnection, localConnection, &c.requestWaitGroup)

	// wait for data transfer to finish before closing the stream
	c.requestWaitGroup.Wait()

	return nil
}

// Pipe the data between two connections
func proxy(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dst, src)
}
