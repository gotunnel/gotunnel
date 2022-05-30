<img src="assets/logo.png" alt="gotunnel" width="150"/>
<br>
<br>

Importable Go library that can be embedded inside your code to expose your locally running service to a public server. It serves as an open-source alternative to ngrok.

Almost every alternative project is either not open-source or exists as a standalone service or CLI that has to be run separately on your server. And can't be directly imported inside your code. This library, however, solves that.

<br>

## Features

- HTTP and HTTPS handling
- Public Key Authentication
- SSL Certificates on Server
- Support for Websockets

### Coming Soon

- Persistent Key-Value Caching on Server
- Connection Callbacks
- Authorized Key Whitelists
- Registration of Reserved Hosts
- Rate Limiting Per Connection
- Load Balancer for the Server
- SSH Tunnels

## Use Cases

- Alternative for preview environments
- Design prototyping and collaboration
- Hosting a game server from home
- Developing webhook integrations
- Managing IoT devices
- And more!

<br>

# Contents

- [Installation](#installation)
  * [Library](#library)
  * [Server](#server)
  * [CLI](#cli)
- [Usage](#usage)
  * [Client](#client)
  * [Server](#server)
    * [Authentication Middleware](#authentication-middleware)
  * [CLI](#cli)
  * [Blank Local app](#blank-local-app)
  * [Existing Remote app](#existing-remote-app)
  * [Environment Variables](#environment-variables)
  * [Debugging](#debugging)
- [Support Us](#support)
- [Dependencies](#dependencies)
- [Advanced Usage](https://github.com/gotunnel/gotunnel/wiki)

<br>

# Installation

## Library

Run:

```
go get -u github.com/gotunnel/gotunnel
```

## Server

We will soon launch a pre-built server package. Stay tuned!

## CLI

We will soon launch a standalone CLI built over `gotunnel` to implement both client and server operations. Stay tuned!

# Usage

## Server

For an HTTPS Server, supply your SSL certificate and it's equivalent key files.

```
log.Fatal(gotunnel.StartServer(&gotunnel.ServerConfig{
        Address:     ":443",
        Certificate: "./server.crt",
        Key:         "./server.key",
}))
```

For an HTTP Server, just don't supply the certificate and key files, and it will automatically
start an HTTP server.

```
log.Fatal(gotunnel.StartServer(&gotunnel.ServerConfig{
        Address:     ":80",
}))
```

### Authentication Middleware

A function that you can attach to the server for authenticating every tunnel creation request,
before you begin the process of creating the tunnel.

Example: At Nhost, we want to ascertain that the user sending a new tunnel creation request from our CLI client, actually has an Nhost account or not, along with their auth tokens.

You can supply your custom authentication function.

It takes an HTTP request and returns an error. If the error is nil, then authentication is complete, and server will continue with the tunnel creation procedure. If the error is NOT nil, server will return the error, to the client, without proceeding ahead with hijacking.

```
func authenticate (r *http.Request) error {
    // perform authentication
}

log.Fatal(gotunnel.StartServer(&gotunnel.ServerConfig{
        Address:     ":80",
        Auth: authenticate,
}))
```

## Client

Simple client, without listening for state changes for established tunnel. The `token` must be unique for every client-server connection you create. This token is also used as an identifier by the server to filter and proxy requests.

```
client := &gotunnel.Client{
    Address: "sub.example.com:443",
    Token:   "your_secret_token",

    // Local port to route incoming requests to
    Port:    "8080",
}

if err := client.Connect(); err != nil {
    return err
}
```

For more professional debugging, you can attach a read-only go channel which will record real-time status of your tunnel.

```
state := make(chan *gotunnel.ClientState)

client := &gotunnel.Client{
    Address: "sub.example.com:443",
    Token:   "your_secret_token",
    Port:    "8080",
    State:   state,
}

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

# Support

- buying sponsorships please!
- To report bugs, or request new features, please open an issue.
- For urgent support, DM me on [Twitter](https://twitter.com/MrinalWahal).

# Dependencies

This project is dependent on following services and libraries:

- [Koding Websockets](https://github.com/koding/websocketproxy)
