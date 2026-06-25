package main

import (
	"flag"
	"fmt"

	"github.com/IamPierrot/simple_dns_blocker/internal/server"
)

type Options struct {
	port uint
}

func main() {
	opts := ExtractFlags()

	if opts.port > 65535 {
		panic("WTF is that port?")
	}

	srv := server.New(opts.port)

	defer srv.Close()

	if err := srv.Start(); err != nil {
		fmt.Printf("Lỗi nghiêm trọng: %v\n", err)
	}
}

func ExtractFlags() Options {
	portPtr := flag.Uint("port", 2053, "The host's port to bind")

	flag.Parse()

	return Options{
		port: *portPtr,
	}
}
