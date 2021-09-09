package tunnels

import (
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"strconv"
)

func GetPort(low, hi int) int {

	// generate a random port value
	port := strconv.Itoa(low + rand.Intn(hi-low))

	// validate wehther the port is available
	if !portAvaiable(port) {
		return GetPort(low, hi)
	}

	// return the value, if it's available
	response, _ := strconv.Atoi(port)
	return response
}

func portAvaiable(port string) bool {

	ln, err := net.Listen("tcp", ":"+port)

	if err != nil {
		return false
	}

	ln.Close()
	return true
}

func scheme(conn net.Conn) (scheme string) {
	switch conn.(type) {
	case *tls.Conn:
		scheme = "https"
	default:
		scheme = "http"
	}

	return
}

// async is a helper function to convert a blocking function to a function
// returning an error. Useful for plugging function closures into select and co
func async(fn func() error) <-chan error {
	errChan := make(chan error)
	go func() {
		select {
		case errChan <- fn():
		default:
		}

		close(errChan)
	}()

	return errChan
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
