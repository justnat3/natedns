package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/justnat3/natedns/internal/dns"
)

// ResolverCache is a structure of the resolver to hold some kind of state of
// from root resolutions, and previously resolved domains
type ResolverCache struct {
	Nameservers []dns.Record          // the name servers that we know about
	Names       map[string]dns.Record // the names that we have resolved.
}

type Resolver struct {
	activeQ int
	// this should prob be a chan
	qList       ResolverCache
	retransmits int
}

func main() {
	// TODO(nate): printable manfiest of a root file
	cache := RCacheFromFile("./root.domain")
	// println(len(cache.Names))
	// spew.Dump(cache)

	fmt.Println("Resolver Loaded...")
	addr := net.UDPAddr{Port: 2054, IP: net.IPv4zero}
	conn, err := net.ListenUDP("udp", &addr)
	// FIXME(nate): this should not panic
	if err != nil {
		panic(err)
	}

	bb := make([]byte, 128)
	for {
		rlen, _, err := conn.ReadFromUDP(bb)
		// FIXME(nate): this should not panic
		if err != nil {
			panic(err)
		}
		if rlen > 2 {
			break
		}
	}
	defer conn.Close()

	message := dns.ParseMsg(bb)
	println("QUESTION", message.Question.Domain)
	message.Header.RD = false
	parseMsg := message.Bytes()

	serve := 0

	addr_ := cache.Names[cache.Nameservers[serve].Domain]
	raddr := &net.UDPAddr{Port: 53, IP: addr_.Addr}

	spew.Dump("using", raddr)
	retmsg := NameServerSend(parseMsg, raddr, conn)
	if retmsg.Header.RCode == dns.NXDomain {
		println("NXDOMAIN does not exist")
		return
	}
	for retmsg.Records[serve].Domain != message.Question.Domain {

		retmsg.Print()
		if retmsg.Header.RCode != dns.NoError {
			spew.Dump(retmsg)
			panic(retmsg.Header.RCode.String())
		}

		spew.Dump("using", raddr.IP)
		retmsg = NameServerSend(parseMsg, raddr, conn)
		for _, r := range retmsg.Records {
			if r.Addr == nil {
				continue
			}
			raddr = &net.UDPAddr{Port: 53, IP: r.Addr}
		}
	}

	println("ANSWER")
	spew.Dump(retmsg)

	return

}

func NameServerSend(msg []byte, raddr *net.UDPAddr, conn *net.UDPConn) *dns.Msg {
	_, err := conn.WriteToUDP(msg, raddr)
	// FIXME(nate): this should not panic
	if err != nil {
		panic(err)
	}

	rbb := make([]byte, 512)

	for {
		rrlen, _, err := conn.ReadFromUDP(rbb)
		// FIXME(nate): this should not panic
		if err != nil {
			panic(err)
		}
		if rrlen > 2 {
			println("--READ FROM UDP---")
			break
		}
	}

	return dns.ParseMsg(rbb)
}

func RCacheFromFile(p string) ResolverCache {

	f, err := os.Open(p)
	// FIXME(nate): this should not panic
	if err != nil {
		panic(err)
	}
	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)

	var line int
	cache := ResolverCache{
		Names:       make(map[string]dns.Record),
		Nameservers: make([]dns.Record, 0, 10),
	}

	for s.Scan() {
		line++
		if len(s.Text()) > 0 {
			// NOTE(nate): ignore commnets
			if s.Text()[0] == 0x3b {
				continue
			}
		}

		line := strings.TrimLeft(s.Text(), " ")
		if len(line) < 1 {
			continue
		}

		if line[0] == '#' {
			continue
		}

		// FIXME(nate): this is a really supid way of cleaning these lines
		clean := strings.ReplaceAll(s.Text(), "\t", " ")
		splt := strings.Split(clean, " ")

		if len(splt) < 2 {
			continue
		}

		// FIXME(nate): this is also part of the stupidity
		tmp := make([]string, 0, 4)
		for _, s := range splt {
			if s != "" {
				tmp = append(tmp, s)
			}
		}

		// FIXME(nate): this is perhaps also really stupid
		n, err := strconv.Atoi(tmp[1])

		// FIXME(nate): this should not panic
		if err != nil {
			panic(err)
		}

		rec := dns.Record{
			// Domain: tmp[0],
			Class: dns.In,
			Type:  dns.TypeFromString(tmp[2]),
			TTL:   int32(n),
		}

		if rec.Type == dns.Unknown {
			continue
		}

		if rec.Type == dns.Ns {
			rec.Domain = tmp[3]
			cache.Nameservers = append(cache.Nameservers, rec)
			continue
		}

		rec.Domain = tmp[0]
		rec.Addr = net.ParseIP(tmp[3])

		if _, ok := cache.Names[rec.Domain]; ok {
			// dupe found?
			println("duplicate non-ns record")
			spew.Dump(rec)
			os.Exit(1)
		}

		cache.Names[rec.Domain] = rec
	}

	return cache
}
