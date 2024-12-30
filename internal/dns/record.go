package dns

import "net"

type Record struct {
	Type  QueryType
	Class QueryClass
	TTL   uint32
	Addr  net.IP
	// NOTE(nate): likely unused
	Len    *uint16
	Domain string
}

type recordOption func(*Record)

func WithAddr(ip net.IP) recordOption {
	return func(r *Record) {
		r.Addr = ip
	}
}

func WithDomain(s string) recordOption {
	return func(r *Record) {
		r.Domain = s
	}
}

func newRecord(_class QueryClass, _type QueryType, ttl uint32, len *uint16, opts ...recordOption) Record {
	record := Record{
		Class: _class,
		Type:  _type,
		TTL:   ttl,
		Len:   len,
	}

	for _, o := range opts {
		o(&record)
	}

	return record
}
