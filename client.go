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
)

type (
	/* 	Credentials struct {
	   		username string
	   		password string
	   	}
	*/
	Client struct {

		//	Prased URL of the remote address.
		remote *url.URL

		//	Local port you want to expose to the outside world.
		port string

		//	Unique identifier for storing the tunnel tunnel.
		identifier string

		//	Client configuration structure.
		config *ClientConfig

		// Read-only Channel on which tunnel's
		// current state is transmitted to.
		state chan<- *TunnelState

		// Contains the established tunnel state
		// tunnel tunnel

		session *yamux.Session

		requestWaitGroup sync.WaitGroup
		tunnelWaitGroup  sync.WaitGroup

		//	Custom Logger
		log *log.Logger
	}

	//	Client configuration struct
	ClientConfig struct {

		// Hostname on which tunnel is listening for public tunnels.
		// Example: https://wahal.tunnel.wah.al:443
		Address string

		// Local port you want to expose to the outside world.
		// Bascially, the port on which you want to receive
		// incoming proxy requests through the tunnel.
		Port string

		//	Custom Logger.
		//	If not supplied, no logging output will be printed.
		Logger *log.Logger

		//	Skip verifying TLS certificate for the server.
		//	Value should be the same as what you used in server configuration.
		//	By default, this will be false.
		//	Disabling certificate verification makes your tunnel vulnerable to man-in-the-middle attacks.
		InsecureSkipVerify bool

		// Authentication token.
		// Will also be used as a unique identifier
		// by the server for storing tunnel tunnel.
		Token string

		//	Basic Auth.
		//	To password-protect your expose server.
		//	Every visitor must have the credentials to access the tunnel back to your localhost.
		//	BasicAuth Credentials

		// Read-only Channel on which tunnel's
		// current state is transmitted to.
		//
		// It's advisable to assign this channel,
		// for better debugging on the vendor's side.
		State chan<- *TunnelState
	}
)

//	Create a new client from supplied configuration.
func NewClient(config *ClientConfig) (*Client, error) {

	var err error

	client := &Client{
		port:       config.Port,
		identifier: config.Token,
		config:     config,
		log:        &log.Logger{},
	}

	if config.State != nil {
		client.state = config.State
	}

	client.remote, err = url.Parse(config.Address)
	if err != nil {
		return client, err
	}

	if config.Logger == nil {
		client.log.SetOutput(ioutil.Discard)
	} else {
		client.log = config.Logger
	}

	return client, nil
}

// update client's tunnel states
func (c *Client) changeState(value TunnelState) {

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

	//	Check whether it's a TLS tunnel.
	switch c.remote.Scheme {
	case "https", "wss":

		//	TLS configuration
		conf := &tls.Config{
			InsecureSkipVerify: c.config.InsecureSkipVerify,
		}

		// Get a TLS tunnel
		conn, err = tls.Dial(getNetwork(TCP), c.remote.Host, conf)
		if err != nil {
			return err
		}

	default:

		// Get a normal TCP tunnel
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

	// wait until previous listening funcs observes distunnel
	c.tunnelWaitGroup.Wait()

	// Now that the server has responded well on your request,
	// the server should have ideally hijacked your request connect
	// and might perform a handshake.

	// Setup client side of yamux
	c.log.Println("Starting new yamux client")
	c.session, err = yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	// open a new stream with server
	var stream net.Conn

	// if we don't receive anything from the server, we'll timeout
	// this is blocking until server accepts our session
	openStream := func() error {

		// this is blocking until server accepts our session
		stream, err = c.session.Open()
		return err
	}

	select {
	case err := <-async(openStream):
		c.log.Println("opening new stream w/ server")
		if err != nil {
			return fmt.Errorf("session could not be opened: %s", err)
		}
	case <-time.After(DefaultTimeout):
		if stream != nil {
			stream.Close()
		}
		return errors.New("timeout opening session")
	}

	c.log.Println("sending handshake request to server")
	//	Now that you have successfuly opened a session,
	//	send a handshake request to the server.
	if err := handshake(stream); err != nil {
		return err
	}

	// Now that we've completed the handshake,
	// the tunnel has been established.
	// Save this tunnel

	tunnel := tunnel{
		dec:   json.NewDecoder(stream),
		enc:   json.NewEncoder(stream),
		conn:  stream,
		host:  c.remote.Host,
		port:  c.port,
		token: c.identifier,
	}

	// c.tunnel = tunnel

	// update client State
	c.changeState(Connected)

	// Start listening for incoming messages
	// in a separate goroutine
	return c.listen(&tunnel)
}

//	Performs a handshake request with supplied connection.
func handshake(conn net.Conn) error {

	if _, err := conn.Write([]byte(HandshakeRequest)); err != nil {
		return fmt.Errorf("writing handshake request failed: %s", err)
	}

	// Read the server's response to your handshake request
	buf := make([]byte, len(HandshakeResponse))
	if _, err := conn.Read(buf); err != nil {
		return fmt.Errorf("reading handshake response failed: %s", err)
	}

	// If the server has rejected your handshake, then end this mess right here right now
	if string(buf) != HandshakeResponse {
		return fmt.Errorf("invalid handshake response, received: %s", string(buf))
	}

	return nil
}

func (c *Client) listen(conn *tunnel) error {
	c.tunnelWaitGroup.Add(1)
	defer c.tunnelWaitGroup.Done()

	for {
		var msg Protocol
		if err := conn.dec.Decode(&msg); err != nil {

			//	Wait until all requests are finished
			c.requestWaitGroup.Wait()

			//	Gracefully shutdown
			c.Shutdown()

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

				// Tunnel the request to the local client.
				if err := c.tunnel(remote); err != nil {
					c.log.Println(err)
					c.log.Println("failed to proxy data through tunnel")
				}
			}()
		}
	}
}

//	Tunnel the request to locally running client.
func (c *Client) tunnel(remoteConnection net.Conn) error {

	// Dial TCP connection with the local client.
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

//	Copy the data between two tunnels
func proxy(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dst, src)
}

//	Gracefully disconnect the client from the server.
func (c *Client) Shutdown() error {

	if err := c.session.GoAway(); err != nil {
		return err
	}

	c.changeState(Disconnected)

	return c.session.Close()
}
