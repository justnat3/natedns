package dns

import (
	"errors"
	"fmt"
)

var (
	ErrorNoLabelToWrite = errors.New("domain-to-label: no label to write")
)

type Header struct {
	ID uint16 // message id

	// fields
	QR         QR                 // query or response respectively
	OpCode     Opcode             // 0 std, 1 inverse, 2 server status, 3-15 reserved
	AuthAnswer Authoritative      // authoritative
	Trunc      Truncation         // truncation
	RD         RecursionDesired   // recursion desired
	RA         RecursionAvailable // recursion available
	RCode      ResponseCode       // response code, see rcodefailure
	z          uint8              // future use

	// counters
	Questions   uint16 // how many questions
	Answerse    uint16 // how many answers
	Authorities uint16 // how many rr records in authority records
	Additional  uint16 // rr records in additional records
}

func (hdr Header) String() string {
	newline :=
		"id: %d\n qr: %s\n opcode: %s\n aa: %s\n tc: %s\n rd: %s\n ra: %s\n z: %s\n rcode: %s\n questions: %d\n answers: %d\n author: %d\n add: %d"
	return fmt.Sprintf(
		newline,
		hdr.ID,
		hdr.QR,
		hdr.OpCode,
		hdr.AuthAnswer,
		hdr.Trunc,
		hdr.RD,
		hdr.RA,
		hdr.z,
		hdr.RCode,
		hdr.Questions,
		hdr.Answerse,
		hdr.Authorities,
		hdr.Additional,
	)
}

func (h *Header) parseHdrFlags(qinfo uint16) {
	lower := uint8(qinfo >> 8)
	upper := uint8(qinfo & 0xff)
	h.RD = RecursionDesired(lower & (1 << 0))
	h.Trunc = Truncation(lower & (1 << 1))
	h.AuthAnswer = Authoritative(lower & (1 << 2))
	h.OpCode = Opcode((lower >> 3) & 0x0f)
	h.QR = QR(0)
	if lower&(1<<7) > 0 {
		h.QR = QR(1)
	}
	h.RA = RecursionAvailable((upper & (1 << 6)))
	h.z = uint8((upper & (1 << 1)) & 0xf0)
	h.RCode = ResponseCode(upper & 0x0f)
}

func (hdr Header) write() []byte {
	buff := []byte{
		uint8(hdr.ID >> 8),
		uint8(hdr.ID & 0xff),
		(uint8(hdr.RD) |
			uint8(hdr.Trunc)<<1 |
			uint8(hdr.AuthAnswer)<<2 |
			uint8(hdr.OpCode)<<3 |
			uint8(hdr.RA)<<7),
		uint8(hdr.RCode),
		uint8(hdr.Questions >> 8),
		uint8(hdr.Questions & 0xff),
		uint8(hdr.Answerse >> 8),
		uint8(hdr.Answerse & 0xff),
		uint8(hdr.Authorities >> 8),
		uint8(hdr.Authorities & 0xff),
		uint8(hdr.Additional >> 8),
		uint8(hdr.Additional & 0xff),
	}

	return buff
}

type Question struct {
	// question name could be like "google.com"
	Domain string

	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
	Type QueryType

	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
	Class QueryClass
}

func (q Question) write() []byte {
	return nil
}

func (q Question) String() string {
	return fmt.Sprintf(
		"question: %s\nqtype: %d\nqclass: %d",
		string(q.Domain),
		q.Type,
		q.Class,
	)
}

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
