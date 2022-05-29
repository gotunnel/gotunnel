package tunnels

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"log"

	"github.com/hashicorp/yamux"
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

type Client struct {

	// Hostname on which tunnel is listening for public connections.
	// Example: wahal.tunnel.wah.al:443
	Address string

	// Local port you want to expose to the outside world.
	// Bascially, the port on which you want to receive
	// incoming proxy requests through the tunnel.
	Port string

	// Authentication token
	// Will also be used as a unique identifier
	// by the server for storing tunnel connection
	Token string

	// Read-only Channel on which connection's
	// current state is transmitted to.
	//
	// It's advisable to assign this channel,
	// for better debugging on the vendor's side.
	State chan<- *ClientState

	// Contains the established connection state
	// connection connection

	session *yamux.Session

	requestWaitGroup    sync.WaitGroup
	connectionWaitGroup sync.WaitGroup
}

// Initialize the client
// make sure configurations are correct
// and that we can move ahead to connect
func (c *Client) Init() error {

	// Ensure the remote host is reachable
	_, err := net.Dial("tcp", c.Address)
	if err != nil {
		return err
	}

	// Ensure the local host is reachable
	_, err = net.Dial("tcp", ":"+c.Port)
	if err != nil {
		return err
	}

	return nil
}

// update client's connection states
func (c *Client) changeState(value ClientState) {
	newState := value

	if c.State != nil {
		c.State <- &newState
	} else {
		c.State = make(chan *ClientState)
		c.State <- &newState
	}
}

func (c *Client) Connect() error {

	// set client State
	c.changeState(Connecting)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Get a TLS connection
	conn, err := tls.Dial("tcp", c.Address, conf)
	if err != nil {
		return err
	}

	remoteURL := fmt.Sprint(scheme(conn), "://", conn.RemoteAddr(), CONNECTION_PATH)
	req, err := http.NewRequest(http.MethodConnect, remoteURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request to %s: %s", remoteURL, err)
	}

	// Set the auth token in gotunnel identification header
	req.Header.Set(TokenHeader, c.Token)

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
	// and might perform a handshake

	// Setup client side of yamux
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
		if err != nil {
			return fmt.Errorf("waiting for session to open failed: %s", err)
		}
	case <-time.After(DefaultTimeout):
		if stream != nil {
			stream.Close()
		}
		return errors.New("timeout opening session")
	}

	// Send a handshake request
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
		dec:  json.NewDecoder(stream),
		enc:  json.NewEncoder(stream),
		conn: stream,
		host: c.Address,
		port: c.Port,
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
					log.Println(err)
					log.Println("failed to proxy data through tunnel")
				}
			}()
		}
	}
}

// Tunnel the request to locally running reverse proxy
func (c *Client) tunnel(remoteConnection net.Conn) error {

	// Dial TCP connection with locally running reverse proxy server
	localConnection, err := net.Dial("tcp", ":"+c.Port)
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
