# gotunnel

Importable Go library that can be embedded inside your code to expose your locally running service to a public server. It serves as an open-source alternative to ngrok.

## Features

- HTTP and HTTPS handling
- SSL Certificates on Server
- Active tunnels and sessions are persisted in-memory cache.
- Connection Callbacks
- Auto-Reconnect the Client

### Coming Soon

- Authorized Key Whitelists
- Support for Websockets
- Registration of Reserved Hosts
- Rate Limiting Per Connection
- Load Balancer for the Server
- SSH Tunnels
- Public Key Authentication


# Installation

```
go get -u github.com/gotunnel/gotunnel
```

# Usage

## Server

For a simple HTTP server, just supply the local port you want to expose.

```
log.Fatal(gotunnel.StartServer(&gotunnel.ServerConfig{
        Address:     ":80",
        InsecureSkipVerify: true,
}))
```

For an HTTPS Server, supply your SSL certificate and it's equivalent key files.

```
log.Fatal(gotunnel.StartServer(&gotunnel.ServerConfig{
        Address:     ":443",
        Certificate: "./server.crt",
        Key:         "./server.key",
}))
```

### Authentication Middleware

On server side, you can supply a custom authentication function that will be executed when a new tunnel creation request is received by the server. It takes an HTTP request and returns an error.

For example, you can use it to authenticate the users who are requesting a new tunnel from your server.

```
func authenticate (r *http.Request) error {
    // perform authentication
}

log.Fatal(gotunnel.StartServer(&gotunnel.ServerConfig{
        Address:     ":80",
        Auth: authenticate,
}))
```

### Callback Functions

These are specialized functions that if supplied, are triggered on specific client state changes.

For example, the `OnConnection` callback function is triggered once a new tunnel is successfully established.

```
log.Fatal(gotunnel.StartServer(&gotunnel.ServerConfig{
	Address:            ":5000",
	InsecureSkipVerify: true,
	Callbacks: gotunnel.Callbacks{
		OnConnection: func(w http.ResponseWriter, r *http.Request) error {
			w.Write([]byte("Hello World!"))
			return nil
		},
	},
}))
```

## Client

Simple client, without listening for state changes for established tunnel. The `token` must be unique for every client-server tunnel you create. This token is also used as an identifier by the server to filter and proxy requests.

```
client := &gotunnel.ClientConfig{
    Address: "sub.example.com:80",
    Token:   "your_secret_token",

    // Local port to route incoming requests to
    Port:    "8080",
    InsecureSkipVerify: true,
}

if err := client.Connect(); err != nil {
    return err
}
```

For more professional debugging, you can attach a read-only go channel which will record real-time status of your tunnel.

```
state := make(chan *gotunnel.ClientState)

client, _ := gotunnel.NewClient(&gotunnel.ClientConfig{
    Address: "sub.example.com:443",
    Token:   "your_secret_token",
    Port:    "8080",
    State:   state,
})

go func() {
    for {
        change := <-state
        if *change == gotunnel.Connecting {
            log.Println("Connecting")
        } else if *change == gotunnel.Connected {
            log.Println("Connected")
        } else if *change == gotunnel.Disconnected {
            log.Println("Disconnected")
        }
    }
}()

if err := client.Connect(); err != nil {
    return err
}
```

### Client Auto-Reconnect

You can watch the `gotunnel.Disconnected` state change, and use it to re-connect your client to the server.

------------------------------------

**Example: Reconnect With Exponential Backoff**

You can use a simple backoff library in golang like [`github.com/jpillora/backoff`](https://github.com/jpillora/backoff) to attempt reconnection in exponential intervals.

```
state := make(chan *gotunnel.ClientState)

client, _ := gotunnel.NewClient(&gotunnel.Client{
    Address: "sub.example.com:443",
    Token:   "your_secret_token",
    Port:    "8080",
    State:   state,
})

b := &backoff.Backoff{
    Max:    5 * time.Minute,
}

var err error

go func() {
    for {
        change := <-state
        if *change == gotunnel.Disconnected {
            time.Sleep(b.Duration())
            err = client.Connect()
        }
    }
}()

if err = client.Connect(); err != nil {
    return err
}
```