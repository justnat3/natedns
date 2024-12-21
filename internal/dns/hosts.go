package dns

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"
)

var (
	ErrorNoHosts = errors.New("parse-hosts: no hosts in this file.")
)

type HostEntry struct {
	IP        net.IP
	FQDN      string
	aliasList []string
}

func ParseHosts(file string) ([]HostEntry, error) {
	// TODO(nate): for now we just support etc/hosts
	file = "/etc/hosts"
	out := make([]HostEntry, 0, 15)

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)

	for s.Scan() {
		line := strings.TrimLeft(s.Text(), " ")
		if len(line) < 1 {
			continue
		}

		if line[0] == '#' {
			continue
		}

		clean := strings.ReplaceAll(s.Text(), "\t", " ")
		splt := strings.Split(clean, " ")
		if len(splt) < 2 {
			continue
		}

		var nsplt []string
		for _, s := range splt {
			if s == "" {
				continue
			}
			nsplt = append(nsplt, s)
		}

		if len(nsplt) < 2 {
			continue
		}
		ip := net.ParseIP(nsplt[0])
		// ignore
		if ip == nil {
			continue
		}

		he := HostEntry{IP: ip, FQDN: nsplt[1], aliasList: nsplt[1:]}
		out = append(out, he)
	}

	if len(out) < 1 {
		return nil, ErrorNoHosts
	}

	return out, nil
}
