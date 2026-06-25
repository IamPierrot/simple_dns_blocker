package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/IamPierrot/simple_dns_blocker/internal/server"
)

type Options struct {
	ip   string
	port uint
}

func main() {
	opts := ExtractFlags()

	if opts.port > 65535 {
		panic("WTF is that port?")
	}

	if net.ParseIP(opts.ip) == nil || net.ParseIP(opts.ip).To4() == nil {
		panic("WTF is that Ipv4 ?")
	}

	srv := server.New(opts.ip, opts.port)

	defer srv.Close()

	if err := srv.Start(); err != nil {
		fmt.Printf("Lỗi nghiêm trọng: %v\n", err)
	}
}

func ExtractFlags() Options {
	ipPtr := flag.String("ip", "127.0.0.1", "The host's Ipv4 address to bind")
	portPtr := flag.Uint("port", 2053, "The host's port to bind")

	flag.Parse()

	return Options{
		ip:   *ipPtr,
		port: *portPtr,
	}
}
