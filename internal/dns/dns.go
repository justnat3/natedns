package dns

import (
	"fmt"
)

type header struct {
	id uint16 // message id

	// fields
	queryReponse        QR                 // query or response respectively
	opcode              Opcode             // 0 std, 1 inverse, 2 server status, 3-15 reserved
	authoritativeAnswer Authoritative      // authoritative
	truncation          Truncation         // truncation
	recursionDesired    RecursionDesired   // recursion desired
	recursionAvaiable   RecursionAvailable // recursion available
	reponseCode         ResponseCode       // response code, see rcodefailure
	z                   uint8              // future use

	// counters
	questions uint16 // how many questions
	answers   uint16 // how many answers
	nsRecs    uint16 // how many rr records in authority records
	addRecs   uint16 // rr records in additional records
}

func (hdr header) String() string {
	newline :=
		"id: %d\n qr: %s\n opcode: %s\n aa: %s\n tc: %s\n rd: %s\n ra: %s\n z: %s\n rcode: %s\n questions: %d\n answers: %d\n author: %d\n add: %d"
	return fmt.Sprintf(
		newline,
		hdr.id,
		hdr.queryReponse,
		hdr.opcode,
		hdr.authoritativeAnswer,
		hdr.truncation,
		hdr.recursionDesired,
		hdr.recursionAvaiable,
		hdr.z,
		hdr.reponseCode,
		hdr.questions,
		hdr.answers,
		hdr.nsRecs,
		hdr.addRecs,
	)
}

func (h *header) parseHdrFlags(qinfo uint16) {
	lower := uint8(qinfo >> 8)
	upper := uint8(qinfo & 0xff)
	h.recursionDesired = RecursionDesired(lower & (1 << 0))
	h.truncation = Truncation(lower & (1 << 1))
	h.authoritativeAnswer = Authoritative(lower & (1 << 2))
	h.opcode = Opcode((lower >> 3) & 0x0f)
	h.queryReponse = QR(0)
	if lower&(1<<7) > 0 {
		h.queryReponse = QR(1)
	}
	h.recursionAvaiable = RecursionAvailable((upper & (1 << 6)))
	h.z = uint8((upper & (1 << 1)) & 0xf0)
	h.reponseCode = ResponseCode(upper & 0x0f)
}

func (hdr header) write() []byte {
	buff := []byte{
		uint8(hdr.id >> 8),
		uint8(hdr.id & 0xff),
		(uint8(hdr.recursionDesired) | uint8(hdr.truncation)<<1 | uint8(hdr.authoritativeAnswer)<<2 | uint8(hdr.opcode)<<3 | uint8(hdr.recursionAvaiable)<<7),
		uint8(hdr.reponseCode),
		uint8(hdr.questions >> 8),
		uint8(hdr.questions & 0xff),
		uint8(hdr.answers >> 8),
		uint8(hdr.answers & 0xff),
		uint8(hdr.nsRecs >> 8),
		uint8(hdr.nsRecs & 0xff),
		uint8(hdr.addRecs >> 8),
		uint8(hdr.addRecs & 0xff),
	}

	return buff
}

type question struct {
	// question name could be like "google.com"
	qname string
	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
	qtype qtype
	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
	qclass class
}

func (q question) write() []byte {
	return nil
}

func (q question) String() string {
	return fmt.Sprintf(
		"question: %s\nqtype: %d\nqclass: %d",
		string(q.qname),
		q.qtype,
		q.qclass,
	)
}

func DomainToLabel(domain string) []byte {
	var buf []byte
	var labels []string

	start := 0
	for i, c := range domain {
		if c != '.' {
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
	return buf
}
