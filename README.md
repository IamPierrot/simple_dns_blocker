# Simple DNS Server for Ads Blocker

Nowadays, people have to cope with annoying advertisements, trackers, and telemetry services while browsing the internet. This project is a simple DNS server written in Go that can block unwanted domains before they are resolved by the operating system.

The primary goal of this project is educational: to learn how the DNS protocol works at a low level, how DNS packets are structured, and how a DNS server communicates over UDP.

## Features

* Parse DNS queries manually
* Resolve and forward DNS requests to upstream DNS servers
* Block domains using a configurable blocklist
* Support wildcard-like blocking through domain suffix matching
* Return custom DNS responses for blocked domains
* Lightweight and dependency-free

## Technologies

This project is built entirely with Go's standard library:

* `net` — UDP networking and DNS forwarding
* `sync` — buffer pooling and concurrency primitives
* `bufio` — efficient blocklist file reading
* `os` — file handling
* `strings` — domain parsing and matching
* `fmt` — logging and debugging

## Project Structure

```text
cmd/
├── config/blocklists
└── server/


internal/
├── blocker/
├── dns/
├── pool/
└── server/
```

## Learning Objectives

This project explores:

* DNS packet structure
* DNS header fields
* Question and Answer sections
* Domain name encoding (QName)
* UDP communication
* DNS forwarding
* Concurrent request handling with goroutines

## How To Run

```bash
go build cmd/server/main.go
./main # or ./main.exe if on windows

./main --help # for more options
```