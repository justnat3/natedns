package main

import (
	"fmt"
	"github.com/justnat3/natedns/internal/dns"
	"net"
)

func main() {
	fmt.Println("Resolver Loaded...")
	addr := net.UDPAddr{Port: 2053, IP: net.ParseIP("127.0.0.1")}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}

	defer conn.Close()

	bb := make([]byte, 1024)
	for {
		rlen, _, err := conn.ReadFromUDP(bb)
		if err != nil {
			panic(err)
		}
		if rlen > 2 {
			break
		}
	}

	message := dns.NewMessage(bb)
	fmt.Println(message.String())
}
