package dns

import "net"

type Record struct {
	_type  QueryType
	_class QueryClass
	ttl    uint32
	addr   net.IP
	len    *uint16
	domain string
}

type recordOption func(*Record)

func WithAddr(ip net.IP) recordOption {
	return func(r *Record) {
		r.addr = ip
	}
}

func WithDomain(s string) recordOption {
	return func(r *Record) {
		r.domain = s
	}
}

func newRecord(_class QueryClass, _type QueryType, ttl uint32, len *uint16, opts ...recordOption) Record {
	record := Record{
		_class: _class,
		_type:  _type,
		ttl:    ttl,
		len:    len,
	}

	for _, o := range opts {
		o(&record)
	}

	return record
}
