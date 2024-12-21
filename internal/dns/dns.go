package dns

import (
	"errors"
	"fmt"
)

type header struct {
	id uint16 // message id

	// fields
	qr         QR                 // query or response respectively
	opcode     Opcode             // 0 std, 1 inverse, 2 server status, 3-15 reserved
	authAnswer Authoritative      // authoritative
	trunc      Truncation         // truncation
	rd         RecursionDesired   // recursion desired
	ra         RecursionAvailable // recursion available
	rcode      ResponseCode       // response code, see rcodefailure
	z          uint8              // future use

	// counters
	questions   uint16 // how many questions
	answers     uint16 // how many answers
	authorities uint16 // how many rr records in authority records
	additional  uint16 // rr records in additional records
}

func (hdr header) String() string {
	newline :=
		"id: %d\n qr: %s\n opcode: %s\n aa: %s\n tc: %s\n rd: %s\n ra: %s\n z: %s\n rcode: %s\n questions: %d\n answers: %d\n author: %d\n add: %d"
	return fmt.Sprintf(
		newline,
		hdr.id,
		hdr.qr,
		hdr.opcode,
		hdr.authAnswer,
		hdr.trunc,
		hdr.rd,
		hdr.ra,
		hdr.z,
		hdr.rcode,
		hdr.questions,
		hdr.answers,
		hdr.authorities,
		hdr.additional,
	)
}

func (h *header) parseHdrFlags(qinfo uint16) {
	lower := uint8(qinfo >> 8)
	upper := uint8(qinfo & 0xff)
	h.rd = RecursionDesired(lower & (1 << 0))
	h.trunc = Truncation(lower & (1 << 1))
	h.authAnswer = Authoritative(lower & (1 << 2))
	h.opcode = Opcode((lower >> 3) & 0x0f)
	h.qr = QR(0)
	if lower&(1<<7) > 0 {
		h.qr = QR(1)
	}
	h.ra = RecursionAvailable((upper & (1 << 6)))
	h.z = uint8((upper & (1 << 1)) & 0xf0)
	h.rcode = ResponseCode(upper & 0x0f)
}

func (hdr header) write() []byte {
	buff := []byte{
		uint8(hdr.id >> 8),
		uint8(hdr.id & 0xff),
		(uint8(hdr.rd) |
			uint8(hdr.trunc)<<1 |
			uint8(hdr.authAnswer)<<2 |
			uint8(hdr.opcode)<<3 |
			uint8(hdr.ra)<<7),
		uint8(hdr.rcode),
		uint8(hdr.questions >> 8),
		uint8(hdr.questions & 0xff),
		uint8(hdr.answers >> 8),
		uint8(hdr.answers & 0xff),
		uint8(hdr.authorities >> 8),
		uint8(hdr.authorities & 0xff),
		uint8(hdr.additional >> 8),
		uint8(hdr.additional & 0xff),
	}

	return buff
}

type question struct {
	// question name could be like "google.com"
	domain string
	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
	_type qtype
	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
	class class
}

func (q question) write() []byte {
	return nil
}

func (q question) String() string {
	return fmt.Sprintf(
		"question: %s\nqtype: %d\nqclass: %d",
		string(q.domain),
		q._type,
		q.class,
	)
}

var (
	ErrorNoLabelToWrite = errors.New("domain-to-label: no label to write")
)

func DomainToLabel(domain string) ([]byte, error) {
	if len(domain) < 1 {
		return nil, ErrorNoLabelToWrite
	}

	var buf []byte
	var labels []string

	start := 0
	for i, c := range domain {
		if c != 0x2e {
			continue
		}

		labels = append(labels, domain[start:i])
		start = i + 1
	}

	labels = append(labels, domain[start:])
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}

	buf = append(buf, 0)
	return buf, nil
}
