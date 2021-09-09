package tunnels

import (
	"bufio"
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

// ClientState represents client connection state to tunnel server.
type ClientState uint32

// ClientState enumeration.
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
	// Example: wahal.tunnel.nhost.io
	Host                string
	Port                string
	LocalPort           string
	Token               string
	session             *yamux.Session
	requestWaitGroup    sync.WaitGroup
	connectionWaitGroup sync.WaitGroup
	state               chan<- *ClientState
}

// Initialize the client
// make sure configurations are correct
// and that we can move ahead to connect
func (c *Client) Init() error {

	// Ensure the remote host is reachable
	_, err := net.Dial("tcp", c.Host+":"+c.Port)
	if err != nil {
		return err
	}

	// Ensure the local host is reachable
	_, err = net.Dial("tcp", ":"+c.LocalPort)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) changeState(value ClientState) {
	newState := value

	if c.state != nil {
		select {
		case c.state <- &newState:
		default:
			log.Printf("Dropping state change due to slow reader: %v", newState)
		}
	} else {
		c.state = make(chan *ClientState)
	}
}

func (c *Client) Connect() error {

	// set client state
	c.changeState(Connecting)

	// Get a TCP connection
	conn, err := net.Dial("tcp", c.Host+":"+c.Port)
	if err != nil {
		return err
	}

	remoteURL := fmt.Sprint(scheme(conn), "://", conn.RemoteAddr(), CONNECTION_PATH)
	req, err := http.NewRequest(http.MethodConnect, remoteURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request to %s: %s", remoteURL, err)
	}

	// Set the auth token in Nhost tunnel identification header
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
		// this is blocking until client opens a session to us
		stream, err = c.session.Open()
		return err
	}

	// if we don't receive anything from the server, we'll timeout
	select {
	case err := <-async(openStream):
		if err != nil {
			return fmt.Errorf("waiting for session to open failed: %s", err)
		}
	case <-time.After(time.Second * 10):
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
		host: c.Host,
		port: c.LocalPort,
	}

	log.Println("Tunnel established successfully from client side")

	// update client state
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

			// update client state
			c.changeState(Disconnected)

			return fmt.Errorf("failure decoding control message: %s", err)
		}

		switch msg.Action {
		case RequestClientSession:
			log.Println("Opening a new stream on server's request")

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
	localConnection, err := net.Dial("tcp", ":"+c.LocalPort)
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

	log.Printf("tunneling %s -> %s", src.RemoteAddr(), dst.RemoteAddr())
	n, err := io.Copy(dst, src)
	log.Printf("tunneled %d bytes %s -> %s: %v", n, src.RemoteAddr(), dst.RemoteAddr(), err)
}

/*
// Open a new stream on existing session.
func stream(session *yamux.Session, action string) (net.Conn, error) {

	// Open a new stream
	var stream net.Conn
	var err error
	act := func() error {

		// this is blocking
		switch action {
		case "open":
			stream, err = session.Open()
		default:
			stream, err = session.Accept()
		}
		return err
	}

	// if we don't receive anything from the server, we'll timeout
	select {
	case err := <-async(act):
		switch action {
		case "open":
			if err != nil {
				return nil, fmt.Errorf("waiting for session to open failed: %s", err)
			}
		}
		return stream, err
	case <-time.After(time.Second * 10):
		switch action {
		case "open":
			if stream != nil {
				stream.Close()
			}
		}
		return nil, errors.New("timeout opening session")
	}
}
*/
