package gotunnel

import (
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	//	Default timeout value used in connection requests.
	DefaultTimeout = 10 * time.Second
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

//	Dials a connection to ping the server
func ping(address string) error {

	_, err := net.DialTimeout("tcp", address, time.Duration(1*time.Second))
	if err != nil {
		return err
	}

	return nil
}

//	Validates whether an array contains a supplied value or not.
func contains[x comparable](payload x, array []x) bool {

	for index := 0; index < len(array); index++ {
		if array[index] == payload {
			return true
		}
	}

	return false
}

func isTLS(conn net.Conn) bool {
	switch conn.(type) {
	case *tls.Conn:
		return true
	default:
		return false
	}
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

// validates whether a given folder/file path exists or not
func pathExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

// headerContains is a copy of tokenListContainsValue from gorilla/websocket/util.go
func headerContains(header []string, value string) bool {
	for _, h := range header {
		for _, v := range strings.Split(h, ",") {
			if strings.EqualFold(strings.TrimSpace(v), value) {
				return true
			}
		}
	}

	return false
}

//	Generate random identifier token for client.
func generateIdentifier(n int) string {

	rand.Seed(time.Now().UnixNano())

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func getHostname(r *http.Request) string {

	//	If it's not an absolute URL,
	//	then use the Host from Request struct.
	//	It is in the form `host:port`.
	//	See: http://golang.org/pkg/http/#Request
	if !r.URL.IsAbs() {
		return r.Host
	}

	return r.URL.Hostname()
}
