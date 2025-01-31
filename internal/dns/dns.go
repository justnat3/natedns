package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrorNoLabelToWrite = errors.New("domain-to-label: no label to write")
)

type Header struct {
	ID uint16 // message id

	// fields
	QR         bool         // query or response respectively
	OpCode     Opcode       // 0 std, 1 inverse, 2 server status, 3-15 reserved
	AuthAnswer bool         // authoritative
	Trunc      bool         // truncation
	RD         bool         // recursion desired
	RA         bool         // recursion available
	RCode      ResponseCode // response code, see rcodefailure
	z          bool         // future use

	// counters
	Questions   uint16 // how many questions
	Answers     uint16 // how many answers
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
		hdr.Answers,
		hdr.Authorities,
		hdr.Additional,
	)
}

func (h *Header) parseHdrFlags(qb uint16) {
	h.QR = qb&_QR != 0
	h.OpCode = Opcode((qb >> 11) & 0xFF)
	h.AuthAnswer = qb&_AA != 0
	h.Trunc = qb&_TC != 0
	h.RD = qb&_RD != 0
	h.RA = qb&_RA != 0
	h.z = qb&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
	h.RCode = ResponseCode(qb & 0xF)
}

const (
	headerSize = 12

	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
)

func (hdr Header) Bytes() []byte {
	var flags uint16

	flags = uint16(hdr.OpCode)<<11 | uint16(hdr.RCode&0xF)
	if hdr.QR {
		flags |= _QR
	}

	if hdr.AuthAnswer {
		flags |= _AA
	}
	if hdr.Trunc {
		flags |= _TC
	}
	if hdr.RD {
		flags |= _RD
	}
	if hdr.RA {
		flags |= _RA
	}

	var b []byte

	b = binary.BigEndian.AppendUint16(b, hdr.ID)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, hdr.Questions)
	b = binary.BigEndian.AppendUint16(b, hdr.Answers)
	b = binary.BigEndian.AppendUint16(b, hdr.Authorities)
	b = binary.BigEndian.AppendUint16(b, hdr.Additional)

	return b
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
	labels := strings.Split(domain, ".")

	for _, l := range labels {
		len := len(l)
		if len == 0 {
			continue
		}
		println("LABEL", len, l)
		buf = append(buf, uint8(len))
		for _, b := range []byte(l) {
			buf = append(buf, b)
		}
	}

	buf = append(buf, 0)
	return buf, nil
}
