package main

import (
	"fmt"
	"net"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/justnat3/natedns/internal/dns"
)

func main() {
	h, err := dns.ParseHosts("")
	if err != nil {
		panic(err)
	}
	spew.Dump(h)
	os.Exit(0)

	fmt.Println("Resolver Loaded...")
	addr := net.UDPAddr{Port: 2054, IP: net.IPv4zero}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}

	bb := make([]byte, 512)
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

	rbb := make([]byte, 512)

	for {
		rrlen, _, err := conn.ReadFromUDP(rbb)
		if err != nil {
			panic(err)
		}
		if rrlen > 2 {
			println("--READ FROM UDP---")
			break
		}
	}

	_ = dns.NewMessage(rbb)
}
