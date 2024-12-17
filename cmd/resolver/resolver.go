package main

import (
	"fmt"
	"net"

	"github.com/davecgh/go-spew/spew"
	"github.com/justnat3/natedns/internal/dns"
)

func main() {
	fmt.Println("Resolver Loaded...")
	addr := net.UDPAddr{Port: 2054, IP: net.IPv4zero}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}

	bb := make([]byte, 128)
	for {
		rlen, _, err := conn.ReadFromUDP(bb)
		if err != nil {
			panic(err)
		}
		if rlen > 2 {
			break
		}
	}
	defer conn.Close()

	message := dns.NewMessage(bb)
	_ = message.Write()

	raddr := &net.UDPAddr{Port: 53, IP: net.IP{8, 8, 8, 8}}

	_, err = conn.WriteToUDP(bb, raddr)
	if err != nil {
		panic(err)
	}

	rbb := make([]byte, 128)

	for {
		rrlen, _, err := conn.ReadFromUDP(rbb)
		if err != nil {
			panic(err)
		}
		if rrlen > 2 {
			println("--READ FROM UDP---")
			spew.Dump(rbb)
			break
		}
	}

	spew.Dump(dns.NewMessage(rbb))
}
