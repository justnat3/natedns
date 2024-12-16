package dns

import (
	"errors"
	"fmt"
	"strings"
)

// header (12 bytes)
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
	questions   uint16 // how many questions
	answers     uint16 // how many answers
	authorities uint16 // how many rr records in authority records
	additionals uint16 // rr records in additional records
}

var (
	ErrorInvalidHeader = errors.New("header: invalid")
)

func (hdr header) String() string {
	newline :=
		"id: %d\n qr: %s\n opcode: %s\n aa: %s\n tc: %s\n rd: %s\n ra: %s\n z: %s\n rcode: %s\n qd: %s\n an: %s\n ns: %s\n ar: %s"
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
		hdr.authorities,
		hdr.additionals,
	)
}

func (h *header) parseQINFO(qinfo uint16) {
	h.queryReponse = QR((qinfo & QrMask) >> 15)
	h.authoritativeAnswer = Authoritative((qinfo & AAMask) >> 10)
	h.truncation = Truncation((qinfo & TCMask) >> 9)
	h.recursionDesired = RecursionDesired((qinfo & RDMask) >> 8)
	h.recursionAvaiable = RecursionAvailable((qinfo & RAMask) >> 7)
	h.z = uint8((qinfo & ZMask) >> 6)
	h.reponseCode = ResponseCode((qinfo & RCodeMask))
	h.opcode = Opcode((qinfo & OPCodeMask) >> 11)
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
		uint8(hdr.authorities >> 8),
		uint8(hdr.authorities & 0xff),
		uint8(hdr.additionals >> 8),
		uint8(hdr.additionals & 0xff),
	}

	return buff
}

type question struct {
	qname  string
	qtype  uint16
	qclass uint16
}

func (m *Msg) parseQuestion() question {
	q := question{}
	q.qname = m.readQName()
	q.qtype = m.reader.read16()
	q.qclass = m.reader.read16()
	return q
}

func (q question) write() []byte {

	buff := []byte{}
	qname := writeQName(q.qname)
	buff = append(buff, qname...)
	s := []byte{
		uint8(q.qtype >> 8),
		uint8(q.qtype & 0xff),
		uint8(q.qclass >> 8),
		uint8(q.qclass & 0xff),
	}
	buff = append(buff, s...)

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

func writeQName(qname string) []byte {
	s := strings.Split(qname, ".")
	var b []byte
	for _, label := range s {
		l := len(label)
		if l > 0x3f {
			return nil
		}
		b = append(b, uint8(l))
		for _, by := range label {
			b = append(b, uint8(by))
		}
	}
	b = append(b, byte(0))
	return b
}

// right now I do not support more than 1 RFC 1035 label
func (m *Msg) readQName() string {
	// this is the initial length

	labelLen := uint8(m.reader.buff[0])
	m.reader.pos++

	// 06 67 6f 6f 67 6c 65 03  63 6f 6d 00  |.google.com.|
	// in this case the first byte is "6" which is "google"
	// then after we've read 6, we get the byte "3" which is "com" and then NULL
	// which means that we are done reading.
	if labelLen > 63 {
		panic(ErrorInvalidQNameLength)
	}

	if len(m.reader.buff) < 1 {
		panic(ErrorInvalidQNameLength)
	}

	str := ""
	for {
		if m.reader.buff[m.reader.pos] == 0 {
			break
		}

		if int(labelLen) == 0 {
			str += string('.')
			labelLen = uint8(m.reader.buff[m.reader.pos])
			m.reader.pos++
		}

		str += string(m.reader.buff[m.reader.pos])
		labelLen--
		m.reader.pos++
	}

	if len(str) < 1 {
		panic(ErrorInvalidQNameLength)
	}

	return str
}

// answer, authority, additional are all types of "resource records"
type resourceRecord struct {
	name   string
	rtype  uint16
	class  uint16
	ttl    uint32
	length uint16
	rdata  uint32
}

func (rr resourceRecord) write() []byte {
	bb := []byte{}
	qname := writeQName(rr.name)
	bb = append(bb, qname...)
	r := []byte{
		uint8(rr.rtype >> 8),
		uint8(rr.rtype & 0xff),
		uint8(rr.class >> 8),
		uint8(rr.class & 0xff),
		uint8((rr.ttl >> 24) & 0xff),
		uint8((rr.ttl >> 16) & 0xff),
		uint8((rr.ttl >> 8) & 0xff),
		uint8((rr.ttl >> 0) & 0xff),
		uint8(rr.length >> 8),
		uint8(rr.length & 0xff),
		uint8((rr.rdata >> 24) & 0xff),
		uint8((rr.rdata >> 16) & 0xff),
		uint8((rr.rdata >> 8) & 0xff),
		uint8((rr.rdata >> 0) & 0xff),
	}
	r = append(r, bb...)
	return r
}

func (m *Msg) parseRR() {
	m.resource.rtype = m.reader.read16()
	m.resource.class = m.reader.read16()
	m.resource.ttl = m.reader.read32()
	m.resource.length = m.reader.read16()
	m.resource.rdata = m.reader.read32()
}
