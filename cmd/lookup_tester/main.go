package main

import (
	"context"
	"fmt"
	"net"
	"os"
)

const server = "0.0.0.0:2054"

func Foo(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, network, server)
}

func main() {
	domain := "example.com"

	resolver := &net.Resolver{PreferGo: true, Dial: Foo}
	_, err := resolver.LookupIPAddr(context.Background(), domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		os.Exit(1)
	}
}
