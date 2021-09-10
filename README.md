# Nhost Tunnels

This feature is still under development.

## Disclaimer

This repo is not fit for production use.

## Installation

Install it with Go: go get github.com/nhost/tunnels

## Usage

Just import the library directly into your code.

### Server

For an HTTPS Server, supply your SSL certificate and it's equivalent key files.

```
log.Fatal(tunnels.StartServer(&tunnels.ServerConfig{
                Address:     ":443",
                Certificate: "./server.crt",
                Key:         "./server.key",
        }))
```

For an HTTP Server.

```
log.Fatal(tunnels.StartServer(&tunnels.ServerConfig{
                Address:     ":80",
        }))
```

### Client

Simple client, without listening for state changes for established tunnel.

```
		client := &tunnels.Client{
			Address: "sub.example.com:443",
			Token:   "your_secret_token",

            // Local port to route incoming requests to
			Port:    "8080",
		}

		if err := client.Connect(); err != nil {
            return err
		}
```

For more professional debugging, you can attach a read-only go channel which will record real-time status
of your tunnel. The client will do the magic of updating these state changes automatically under the hoood.
You just need to supply a channel to receive them.

```
		state := make(chan *tunnels.ClientState)

		client := &tunnels.Client{
			Address: "sub.example.com:443",
			Token:   "your_secret_token",
			Port:    "8080",
			State:   state,
		}

		go func() {
			for {
				change := <-state
				if *change == tunnels.Connecting {
					log.Println("Connecting")
				} else if *change == tunnels.Connected {
					log.Println("Connected")
				} else if *change == tunnels.Disconnected {
					log.Println("Disconnected")
				}
			}
		}()

		if err := client.Connect(); err != nil {
            return err
		}
```