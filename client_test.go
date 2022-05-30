package gotunnel

import (
	"log"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

const (

	//	Remote server address
	remoteAddr = "http://localhost:3000"

	//	Local port
	localPort = "8080"
)

func TestConnection(t *testing.T) {

	//	Initialize a waitgroup
	var wg sync.WaitGroup

	//	Initialize a client state channel
	state := make(chan *ClientState)

	//	Launch a local file server for testing.
	go startFileServer(localPort, ".")

	//	Launch remote proxy server.
	go StartServer(&ServerConfig{
		Address: remoteAddr,
		Logger:  logrus.New(),
	})

	//	Add a delay to allow servers to start.
	time.Sleep(1 * time.Second)

	tests := []struct {
		name    string
		client  Client
		wantErr bool
	}{
		{
			name: "vanilla",
			client: Client{
				Address:            remoteAddr,
				Token:              "secret",
				Port:               localPort,
				State:              state,
				InsecureSkipVerify: true,
				Logger:             logrus.New(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := &tt.client

			//	Initialize the client
			c.Init()

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

						//	Ping the remote server to test the connection.
						if err := ping(TCP, remoteAddr); err != nil {
							t.Errorf("Ping failed, error = %v, wantErr %v", err, tt.wantErr)
						}

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
				}
			}()

			wg.Wait()

			/* 			//	Establish a new session by making a GET request.
			   			_, err := http.Get(remoteAddr)
			   			if err != nil {
			   				t.Errorf("GET request failed, error = %v, wantErr %v", err, tt.wantErr)
			   			}
			*/
		})
	}
}

//	Launches a simple file server in specified directory.
func startFileServer(port, directory string) {

	http.Handle("/", http.FileServer(http.Dir(directory)))

	log.Printf("Serving FS on HTTP port: %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
