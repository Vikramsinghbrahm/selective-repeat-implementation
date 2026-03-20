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
- Sliding-window transmission with adaptive retransmission timeout updates.
- Concurrent multi-session handling on the UDP file server.
- Explicit session lifecycle using `SYN`, `DATA`, and `FIN` control packets.
- Session-bound authenticated payload framing for both control and data packets.
- Randomized session tokens and randomized handshake sequence numbers.
- HTTP/1.0 request and response exchange over the UDP transport.
- File download and upload support through `GET` and `POST`.
- Safe path resolution to prevent escaping the configured server root.
- Transport-level message size caps to bound in-memory request and response assembly.
- Aggregate metrics and transport-aware logging for sessions, retransmissions, and RTO changes.
- Backward-compatible CLI flags for the provided networking workflow.

## Project Layout

```text
.
|-- cmd
|   |-- httpc          # UDP HTTP client CLI
|   |-- httpfs         # UDP file server CLI
|   `-- router         # Cross-platform UDP router CLI
|-- examples
|   `-- data           # Sample files for local testing, including a large text fixture
|-- internal
|   |-- fileserver     # File-serving logic
|   |-- httpwire       # HTTP/1.0 request and response helpers
|   |-- protocol       # Packet definitions and binary encoding
|   |-- router         # Router implementation used by the CLI and Go integration tests
|   `-- transport      # Selective-repeat listener, dialer, and session logic
|-- dist
|   `-- router.exe     # Router binary for local Windows testing
`-- go.mod
```

## Requirements

- Go 1.21.4 or newer
- IPv4 networking
- A compatible UDP router

The repository includes a native Go router in `cmd/router` for cross-platform local runs.
For Windows-based local testing, `dist/router.exe` remains available as a compatibility fallback.

## Build

```powershell
go build -o .\bin\httpc.exe .\cmd\httpc
go build -o .\bin\httpfs.exe .\cmd\httpfs
go build -o .\bin\router.exe .\cmd\router
```

## Testing

Run the full Go test suite, including the cross-platform end-to-end integration test:

```powershell
go test -buildvcs=false ./...
```

Run package tests and rebuild the Windows binaries:

```powershell
.\scripts\Test-Go.ps1
```

Run the local router-based integration suite:

```powershell
.\scripts\Test-E2E.ps1
```

Run the full verification flow:

```powershell
.\scripts\Test-All.ps1
```

The end-to-end script validates:

- small-file `GET`
- small-file `POST` round-trip
- large-file `GET`
- large-file `POST` round-trip
- large-text `GET`
- large-text `POST` round-trip
- concurrent large-file `GET` rounds with SHA-256 verification
- concurrent large-text `GET` rounds with SHA-256 verification

Logs and copied test data are written to a timestamped `.tmp-*` directory in the repository root.
The PowerShell test scripts use the checked-in `examples/data/large.txt` fixture, build the Go router by default, and fall back to `dist/router.exe` only if the built router is unavailable.

## Run Locally

Start the Go router:

```powershell
.\bin\router.exe --port 3000 --drop-rate 0 --max-delay 0ms --seed 1
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
- `--max-message-size`: maximum transport message size in bytes. Default `8388608`.
- `--log-transport`: enable transport session and adaptive RTO logging.
- `--metrics`: print aggregate transport metrics to `stderr` after the request completes.

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
- `--log-transport`: enable transport session and adaptive RTO logging.
- `--timeout`: initial retransmission timeout. Default `2s`.
- `--session-deadline`: per-request deadline. Default `30s`.
- `--metrics-interval`: periodic transport metrics logging interval. Default `0` (disabled).
- `--window-size`: selective-repeat window size. Default `5`.
- `--max-message-size`: maximum transport message size in bytes. Default `8388608`.

### `router`

```text
router [options]
```

Options:

- `--port`: UDP listening port. Default `3000`.
- `--drop-rate`: packet drop probability from `0.0` to `1.0`. Default `0`.
- `--max-delay`: maximum forwarding delay. Default `0s`.
- `--seed`: deterministic random seed. Default `1`.
- `-v`, `--verbose`: enable router logging.

## Protocol Notes

- Packet headers contain packet type, sequence number, peer IPv4 address, peer port, and payload.
- The transport uses per-packet acknowledgment tracking within a fixed send window and adapts its retransmission timeout from observed RTT samples.
- Packet payloads carry a session token plus authenticated framing that protects control and data messages against accidental corruption and cross-session mix-ups.
- `SYN` and `SYN-ACK` establish a session.
- `DATA` and `DATA-ACK` carry request and response payloads.
- `FIN` and `FIN-ACK` terminate a complete logical message.
- The server demultiplexes packets by peer and handles accepted sessions concurrently.
- The router rewrites the embedded peer address on forward so both endpoints can identify their remote peer across the UDP relay.
- Aggregate metrics track session lifecycle, bytes, packets, retransmissions, acknowledgments, and the latest adaptive RTO value.

## Limitations

- The wire format is IPv4-only because packet headers store four-byte IP addresses.
