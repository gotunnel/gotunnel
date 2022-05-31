package gotunnel

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"testing"
	"time"
)

const (

	//	Remote server address
	remoteAddr = "0.0.0.0:3000"

	//	Local port
	localPort = "8080"
)

func TestConnection(t *testing.T) {

	//	Initialize a waitgroup
	var wg sync.WaitGroup

	//	Initialize a client state channel
	state := make(chan *ClientState)

	//	Launch a local file server for testing.
	fsServer := fileServer(localPort, ".")

	//	Launch remote proxy server.
	go StartServer(&ServerConfig{
		Address: remoteAddr,
	})

	//	Add a delay to allow servers to start.
	time.Sleep(1 * time.Second)

	tests := []struct {
		name    string
		config  ClientConfig
		wantErr bool
		run     bool
	}{
		{
			name: "local",
			config: ClientConfig{
				Address:            "http://" + remoteAddr,
				Token:              "secret",
				Port:               localPort,
				State:              state,
				InsecureSkipVerify: true,
			},
			wantErr: false,
			run:     true,
		},
		{
			name: "hosted",
			config: ClientConfig{
				Address:            "http://whatever.tunnel.wah.al:80",
				Token:              "secret",
				Port:               localPort,
				State:              state,
				InsecureSkipVerify: true,
			},
			wantErr: false,
			run:     false,
		},
	}

	for _, tt := range tests {
		if tt.run {
			t.Run(tt.name, func(t *testing.T) {

				c, err := NewClient(&tt.config)
				if err != nil {
					t.Errorf("Failed to create client, err = %v, wantErr %v", err, tt.wantErr)
				}

				//	Start listening on client state channel.
				wg.Add(1)
				go func() {
					for {
						change := <-state

						switch *change {
						case Connecting:
							log.Println("Establishing tunnel")
						case Connected:

							log.Println("Tunnel connected")

							wg.Done()

						case Disconnected:
							log.Println("Tunnel disconnected")
						}
					}
				}()

				//	Connect the client to the server.
				go func() {
					if err := c.Connect(); (err != nil) != tt.wantErr {
						t.Errorf("Client failed to connect, error = %v, wantErr %v", err, tt.wantErr)
						wg.Done()
					}
				}()

				wg.Wait()

				for i := 0; i <= 2; i++ {

					//	Establish a new session by making a GET request.
					resp, err := http.Get("http://" + remoteAddr)
					if err != nil {
						t.Errorf("GET request failed, error = %v, wantErr %v", err, tt.wantErr)
					}

					defer resp.Body.Close()

					body, _ := ioutil.ReadAll(resp.Body)
					fmt.Println(string(body))
				}

				//	Shutdown the client.
				if err := c.Shutdown(); err != nil {
					t.Errorf("Failed to shutdown client, error = %v, wantErr %v", err, tt.wantErr)
				}
			})

		}
	}

	//	Shutdown FS server
	fsServer.Shutdown(context.Background())
}

//	Launches a simple file server in specified directory.
func fileServer(port, directory string) http.Server {

	router := http.NewServeMux()
	router.Handle("/", http.FileServer(http.Dir(directory)))

	server := http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	log.Printf("Serving FS on HTTP port: %s\n", port)
	go server.ListenAndServe()

	return server
}
