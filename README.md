# Selective Repeat Over UDP in Go

This project implements reliable HTTP-style file transfer over UDP using a selective-repeat sliding window protocol. It includes a UDP transport layer, a curl-like client, and a file server that exchanges HTTP/1.0 requests and responses across a router-compatible packet format.

## Overview

The repository is organized around a few focused components:

- A packet protocol with a compact router-compatible wire format.
- A selective-repeat transport layer for reliable UDP delivery.
- An HTTP wire package for request and response encoding.
- A file server that serves and writes files within a configured data directory.
- A command-line client and server built on top of those internal packages.

## Features

- Reliable delivery over UDP using selective repeat.
- Sliding-window transmission with retransmission on timeout.
- Explicit session lifecycle using `SYN`, `DATA`, and `FIN` control packets.
- HTTP/1.0 request and response exchange over the UDP transport.
- File download and upload support through `GET` and `POST`.
- Safe path resolution to prevent escaping the configured server root.
- Backward-compatible CLI flags for the provided networking workflow.

## Project Layout

```text
.
|-- cmd
|   |-- httpc          # UDP HTTP client CLI
|   `-- httpfs         # UDP file server CLI
|-- examples
|   `-- data           # Sample files for local testing
|-- internal
|   |-- fileserver     # File-serving logic
|   |-- httpwire       # HTTP/1.0 request and response helpers
|   |-- protocol       # Packet definitions and binary encoding
|   `-- transport      # Selective-repeat listener, dialer, and session logic
|-- dist
|   `-- router.exe     # Router binary for local Windows testing
`-- go.mod
```

## Requirements

- Go 1.22 or newer
- IPv4 networking
- A compatible UDP router

For Windows-based local testing, the repository includes `dist/router.exe`.

## Build

```powershell
go build -o .\bin\httpc.exe .\cmd\httpc
go build -o .\bin\httpfs.exe .\cmd\httpfs
```

## Run Locally

Start the router:

```powershell
.\dist\router.exe --port 3000 --drop-rate 0 --max-delay 0ms --seed 1
```

Start the file server:

```powershell
.\bin\httpfs.exe -v -p 8007 -d .\examples\data
```

Issue a GET request:

```powershell
.\bin\httpc.exe get --router-host localhost --router-port 3000 http://localhost:8007/sample.txt
```

Issue a POST request:

```powershell
.\bin\httpc.exe post --router-host localhost --router-port 3000 -f .\examples\data\upload.txt http://localhost:8007/uploads/posted.txt
```

## CLI Reference

### `httpc`

```text
httpc get [options] URL
httpc post [options] [-d data | -f file] URL
httpc help [get|post]
```

Common options:

- `-v`, `--verbose`: include the status line and headers in the output.
- `-H`, `--header`: add a request header in `key:value` format. Repeatable.
- `-o`, `--output`: write the response to a file.
- `--router-host`: router hostname. Default `localhost`.
- `--router-port`: router UDP port. Default `3000`.
- `--server-port`: fallback UDP server port when the URL omits a port. Default `8007`.
- `--timeout`: retransmission timeout. Default `2s`.
- `--deadline`: overall request deadline. Default `30s`.
- `--window-size`: selective-repeat window size. Default `5`.

Supported compatibility aliases:

- `--serverhost`
- `--serverport`
- `--routerhost`
- `--routerport`

### `httpfs`

```text
httpfs [options]
```

Options:

- `-p`, `--port`: UDP listening port. Default `8007`.
- `-d`, `--dir`: data directory to expose. Default current directory.
- `-v`, `--verbose`: enable request logging.
- `--timeout`: retransmission timeout. Default `2s`.
- `--session-deadline`: per-request deadline. Default `30s`.
- `--window-size`: selective-repeat window size. Default `5`.

## Protocol Notes

- Packet headers contain packet type, sequence number, peer IPv4 address, peer port, and payload.
- The transport uses per-packet acknowledgment tracking within a fixed send window.
- `SYN` and `SYN-ACK` establish a session.
- `DATA` and `DATA-ACK` carry request and response payloads.
- `FIN` and `FIN-ACK` terminate a complete logical message.

## Limitations

- The wire format is IPv4-only because packet headers store four-byte IP addresses.
- The server processes one session at a time on a single UDP listener.
