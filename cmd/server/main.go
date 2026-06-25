package main

import (
	"fmt"

	"github.com/IamPierrot/simple_dns_blocker/internal/server"
)

func main() {
	srv := server.New("127.0.0.1", 2053)

	defer srv.Close()

	if err := srv.Start(); err != nil {
		fmt.Printf("Lỗi nghiêm trọng: %v\n", err)
	}
}
