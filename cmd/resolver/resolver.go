package main

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/justnat3/natedns/internal/dns"
	"net"
)

func main() {
	fmt.Println("Resolver Loaded...")
	addr := net.UDPAddr{Port: 2053, IP: net.IPv4zero}
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

	//spew.Dump(bb)
	message := dns.NewMessage(bb)
	nb := message.Write()
	raddr := &net.UDPAddr{Port: 53, IP: net.IP{8, 8, 8, 8}}
	rn, err := conn.WriteToUDP(nb, raddr)
	if err != nil {
		panic(err)
	}
	fmt.Println(rn)
	rbb := make([]byte, 128)
	for {
		rrlen, _, err := conn.ReadFromUDP(rbb)
		if err != nil {
			panic(err)
		}
		if rrlen > 2 {
			fmt.Println("recv:", rrlen)
			spew.Dump(rbb)
			break
		}
	}

}
