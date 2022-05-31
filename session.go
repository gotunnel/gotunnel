package gotunnel

import (
	"errors"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

//	Opens a new stream with the supplied yamux session
//	and waits for the other side to accept the stream.
func openStream(session *yamux.Session) (net.Conn, error) {

	var stream net.Conn
	var err error

	// if we don't receive anything from the server, we'll timeout
	// this is blocking until server accepts our session
	openStream := func() error {

		// this is blocking until server accepts our session
		stream, err = session.Open()
		return err
	}

	select {
	case err := <-async(openStream):
		if err != nil {
			if session.IsClosed() {
				return nil, errors.New("session is closed")
			}
			return nil, err
		}
		return stream, nil
	case <-time.After(DefaultTimeout):
		if stream != nil {
			stream.Close()
		}
		return nil, errors.New("timeout opening session")
	}
}

//	Accepts an incoming stream from the supplied yamux session.
func acceptStream(session *yamux.Session) (net.Conn, error) {

	var stream net.Conn
	var err error

	//	If we don't receive anything from the client, we will timeout.
	acceptStream := func() error {
		stream, err = session.Accept()
		return err
	}

	select {
	case err := <-async(acceptStream):
		if err != nil {
			if session.IsClosed() {
				return nil, errors.New("session is closed")
			}
		}
		return stream, err
	case <-time.After(DefaultTimeout):
		return nil, errors.New("timeout getting session")
	}
}
