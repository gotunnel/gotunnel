<div align="center">
<img src="assets/logo.png" alt="gotunnel" width="150"/>
  <!--
  <a href="https://docs.nhost.io/cli">Website</a>
    <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://nhost.io/blog">Blog</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="docs/">Command Docs</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://discord.com/invite/9V7Qb2U">Support</a>
  <br />
  <br />
  -->
</div>

<div align="center">

Importable Go library to expose your locally running service to public internet.

[![Go Report Card](https://goreportcard.com/badge/github.com/gotunnel/gotunnel)](https://goreportcard.com/report/github.com/gotunnel/gotunnel)
  <a href="https://twitter.com/mrinalwahal" target="_blank" rel="noopener noreferrer">
      <img src="https://img.shields.io/twitter/follow/mrinalwahal?style=social" />
    </a>

</div>

# Features

- HTTP and HTTPS handling
- Public Key Authentication
- SSL Protection
- Support for Websockets

## Coming Soon

- SSH Tunnels
- Connection Callbacks
- Authorized Key Whitelists
- Registration of Reserved Hosts
- Rate Limiting Per Connection
- Load Balancer for the Server

# Contents

- [Features](#features)
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


## CLI

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

For an HTTP Server, just don't supply the certificate and key files, and it will automatically
start an HTTP server.

```
log.Fatal(tunnels.StartServer(&tunnels.ServerConfig{
        Address:     ":80",
}))
```

#### Authentication Middleware

A function that you can attach to the server for authenticating every tunnel creation request,
before you begin the process of creating the tunnel.

Example: At Nhost, we want to ascertain that the user sending a new tunnel creation request from our CLI client, actually has an Nhost account or not, along with their auth tokens.

You can supply your custom authentication function.

It takes an HTTP request and returns an error. If the error is nil, then authentication is complete, and server will continue with the tunnel creation procedure. If the error is NOT nil, server will return the error, to the client, without proceeding ahead with hijacking.

```
func authenticate (r *http.Request) error {
    // perform authentication
}

log.Fatal(tunnels.StartServer(&tunnels.ServerConfig{
        Address:     ":80",
        Auth: authenticate,
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

# Usage

Just one command:

    nhost

- On first run in an empty directory, since the directory is not initialized for an Nhost app, it will do so, and launch the development environment.
- From second run onward, it will start app.

You can also execute the aforementioned actions using their specific commands:

1. `nhost init` - to intialize a blank local app in current working directory. Or `nhost init --remote` to clone an existing app from Nhost console.
2. `nhost dev` - to start your app.

## **Blank Local app**

If you do not have an already existing app on Nhost console, and you wish to create a new app on Nhost console and link it automatically to the local environment, then use:

    nhost link

Note: ability to create new apps on Nhost console directly from your local environment is only available in CLI `v0.5.0` or above.

If you have CLI version less than `v0.5.0`, then you need to have an already existing app on Nhost console.

> To upgrade your CLI to latest version, check [this](#installing) out.

## **Existing Remote App**

If you already have a remote app for which you would like to setup a local development environment for, use the following:

    nhost init --remote

This will present you with a list of apps, across all the workspaces, available on [Nhost console](https://console.nhost.io), and you can select any one of those to set up a local environment for.

## Environment Variables

- Default file for environment variables is `{app_root}/.env.development`.
- All variables inside `.env.development` are accessible inside both containers, and functions.

For more detailed information on runtime variables, including how to add environment variables only to specific service containers, and the list of dynamically generated **runtime variables**, [check this out](https://github.com/gotunnel/gotunnel/wiki/Environment#variables).

## Debugging

If you wish to trace the output and check verbose logs for any command, use the global flag `--debug` or `-d`

Example:

    nhost dev -d

This will print the debug logs along with the standard information, warnings and errors.

### ProTip

You can parallely run `nhost logs` to check real time logs of any service container of your choice, while your local environment is already running. And you can also save it's output, by using `--log-file` flag.

<br>

# Functions

All functions must be stored inside the `{app_root}/functions` directory.

When you launch the development environment using `nhost` or `nhost dev`, it will automatically also start your functions server, and display the URL on your terminal, in the following format:

    http://localhost:1337/v1/functions/{function_name}

If you want to call your `functions/hello.js` function, you can call the following route:

    http://localhost:1337/v1/functions/hello

## Runtimes

Nhost CLI currently supports functions in following runtimes:

1. NodeJS (Both Javascript and Typescript)
2. Golang

For more detailed information on Serverless Functions, like hello-world templates, understanding how speed up testing of functions, and some Pro-Tips, check [this out](https://github.com/gotunnel/gotunnel/wiki/Serverless-Functions).

<br>

# Migration

CLI (>= v0.5.0) produces the `nhost/config.yaml` file in your app root in a different format than the legacy CLI, and not to mention reads the same during `nhost dev` command.

Now, if you already have existing Nhost apps initialized in multiple directories, and you upgrade to CLI `v0.5.0` globally, the new CLI may not be able to read the `nhost/config.yaml` files saved in older formats, hence breaking your local development environment.

# Support

- buying sponsorships please!
- To report bugs, or request new features, please open an issue.
- For urgent support, DM me on [Twitter](https://twitter.com/MrinalWahal).

# Dependencies

This project is dependent on following services and libraries:

- [Koding Websockets](https://github.com/koding/websocketproxy)
