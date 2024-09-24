package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/davecgh/go-spew/spew"
)

type qtype = int

// QTYPE fields appear in the question part of a query.  QTYPES are a
// superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
// following QTYPEs are defined:
const (
	Axfr  qtype = iota + 251 // A request for a transfer of an entire zone
	Mailb                    // A request for mailbox-related records (MB, MG or MR)
	Maila                    // A request for mail agent RRs (Obsolete - see MX)
	Star                     // A request for all records
)

const (
	A     qtype = iota + 1 // a host address
	Ns                     // an authoritative name server
	Md                     // a mail destination (Obsolete - use MX)
	Mf                     // a mail forwarder (Obsolete - use MX)
	Cname                  // the canonical name for an alias
	Soa                    // marks the start of a zone of authority
	Mb                     // a mailbox domain name (EXPERIMENTAL)
	Mg                     // a mail group member (EXPERIMENTAL)
	Mr                     // a mail rename domain name (EXPERIMENTAL)
	Null                   // a null RR (EXPERIMENTAL)
	Wks                    // a well known service description
	Ptr                    // a domain name pointer
	Hinfo                  // host information
	Minfo                  // mailbox or mail list information
	Mx                     // mail exchange
	Txt                    // text strings

)

type class = int

const (
	In class = iota + 1 // the Internet
	Cs                  // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	Ch                  // the CHAOS class
	Hs                  // Hesiod [Dyer 87]
	classStar
)

// header (12 bytes)
type header struct {
	id          uint16 // message id
	qr          uint8  // query or response respectively
	opcode      uint8  // 0 std, 1 inverse, 2 server status, 3-15 reserved
	aa          uint8  // authoritative
	tc          uint8  // truncation
	rd          uint8  // recursion desired
	ra          uint8  // recursion available
	z           uint8  // future use
	rcode       uint8  // response code, see rcodefailure
	questions   uint16 // how many questions
	answers     uint16 // how many answers
	authorities uint16 // how many rr records in authority records
	additionals uint16 // rr records in additional records
}

var (
	ErrorInvalidHeader = errors.New("header: invalid")
)

const (
	QrMask     uint16 = 0x8000 // 1 bit
	OPCodeMask        = 0x7800 // 4 bits
	AAMask            = 0x0400 // 1 bit
	TCMask            = 0x0200 // 1 bit
	RDMask            = 0x0100 // 1 bit
	RAMask            = 0x0080 // 1 bit
	ZMask             = 0x0040 // 1 bit
	RCodeMask         = 0x003F // 4 bits
)

type rcodefailure = int

const (
	// No error condition
	RCodeNoError rcodefailure = iota

	// Format error - The name server was unable to interpret the query.
	ErrorFormat

	/* Server failure
	 * The name server was unable to process this query due to a
	 * problem with the name server.
	 */
	ErrorServer

	/* Name Error
	* Meaningful only for responses from an authoritative name
	* server, this code signifies that the domain name referenced in the query does
	* not exist.
	 */
	ErrorName

	// Not Implemented The name server does not support the requested kind of query.
	ErrorNotImplemented

	/* Refused
	 * The name server refuses to perform the specified operation for
	 * policy reasons.  For example, a name server may not wish to provide the
	 * information to the particular requester, or a name server may not wish to
	 * perform a particular operation (e.g., zone
	 */
	ErrorRefused
)

func (hdr header) String(withNewLines bool) string {
	nonewline :=
		"id: %d, qr: %d, opcode: %d, aa: %d, tc: %d, rd: %d, ra: %d, z: %d, rcode: %d, qd: %d, an: %d, ns: %d, ar: %d"
	newline :=
		"id: %d\nqr: %d\nopcode: %d\naa: %d\ntc: %d\nrd: %d\nra: %d\nz: %d\nrcode: %d\nqd: %d\nan: %d\nns: %d\nar: %d"
	if withNewLines {
		return fmt.Sprintf(
			newline,
			hdr.id,
			hdr.qr,
			hdr.opcode,
			hdr.aa,
			hdr.tc,
			hdr.rd,
			hdr.ra,
			hdr.z,
			hdr.rcode,
			hdr.questions,
			hdr.answers,
			hdr.authorities,
			hdr.additionals,
		)
	}
	return fmt.Sprintf(
		nonewline,
		hdr.id,
		hdr.qr,
		hdr.opcode,
		hdr.aa,
		hdr.tc,
		hdr.rd,
		hdr.ra,
		hdr.z,
		hdr.rcode,
		hdr.questions,
		hdr.answers,
		hdr.authorities,
		hdr.additionals,
	)
}

func read16(b []byte) (uint16, []byte) {
	return binary.BigEndian.Uint16(b[0:2]), b[2:]
}

func read32(b []byte) (uint32, []byte) {
	return binary.BigEndian.Uint32(b[0:4]), b[4:]
}

func NewHeader(b []byte) (*header, []byte) {
	spew.Dump(b)
	hdr := &header{}
	hdr.id, b = read16(b)
	qinfo, b := read16(b)
	hdr.qr = uint8((qinfo & QrMask) >> 15)
	hdr.aa = uint8((qinfo & AAMask) >> 10)
	hdr.tc = uint8((qinfo & TCMask) >> 9)
	hdr.rd = uint8((qinfo & RDMask) >> 8)
	hdr.ra = uint8((qinfo & RAMask) >> 7)
	hdr.z = uint8((qinfo & ZMask) >> 6)
	hdr.rcode = uint8((qinfo & RCodeMask))
	hdr.opcode = uint8((qinfo & OPCodeMask) >> 11)
	hdr.questions, b = read16(b)
	hdr.answers, b = read16(b)
	hdr.authorities, b = read16(b)
	hdr.additionals, b = read16(b)
	return hdr, b
}

func (hdr header) Write() []byte {
	buff := []byte{
		uint8(hdr.id >> 8),
		uint8(hdr.id & 0xff),
		(hdr.rd | hdr.tc<<1 | hdr.aa<<2 | hdr.opcode<<3 | hdr.ra<<7),
		(hdr.rcode),
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

func newQuestion(b []byte) (*question, []byte) {
	q := &question{}
	q.qname, b = readQName(b)
	fmt.Println("len:", b[0])
	fmt.Println("name:", q.qname)
	q.qtype, b = read16(b[12:])
	q.qclass, b = read16(b)
	return q, b
}

func (q question) Write() []byte {
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

type Message struct {
	hdr header
	q   question
	rr  resourceRecord
}

func (m Message) String() string {
	return m.hdr.String(true) + "\n" + m.q.String() + "\n" + m.rr.String()
}

var (
	ErrorInvalidQNameLength = errors.New("qname: buffer is empty")
)

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
func readQName(buff []byte) (string, []byte) {
	// this is the initial length

	labelLen := uint8(buff[0])
	buff = buff[1:]

	// 06 67 6f 6f 67 6c 65 03  63 6f 6d 00  |.google.com.|
	// in this case the first byte is "6" which is "google"
	// then after we've read 6, we get the byte "3" which is "com" and then NULL
	// which means that we are done reading.
	if labelLen > 63 {
		panic(ErrorInvalidQNameLength)
	}

	if len(buff) < 1 {
		panic(ErrorInvalidQNameLength)
	}

	str := ""
	pos := 0
	for {
		if buff[pos] == 0 {
			break
		}

		if int(labelLen) == 0 {
			str += string('.')
			labelLen = uint8(buff[pos])
			pos += 1
		}

		str += string(buff[pos])
		labelLen -= 1
		pos += 1
	}

	if len(str) < 1 {
		panic(ErrorInvalidQNameLength)
	}
	return str, buff[pos:]
}

func NewMessage(b []byte) *Message {
	hdr, b := NewHeader(b)
	hdr.Write()
	q, b := newQuestion(b)
	rr, b := newResourceRecord(b)
	rr.name = q.qname
	fmt.Println("resulting length:", len(b), rr.name)
	m := &Message{hdr: *hdr, q: *q, rr: *rr}
	return m
}

func (m Message) Write() []byte {
	bb := []byte{}
	bb = append(bb, m.hdr.Write()...)
	bb = append(bb, m.q.Write()...)
	bb = append(bb, m.rr.Write()...)
	spew.Dump(bb)
	return bb
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

func (rr resourceRecord) Write() []byte {
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

func (rr resourceRecord) String() string {
	return fmt.Sprintf(
		"name: %s\ntype: %d\n class: %d\n ttl: %d\n length: %d\n rdata: %d",
		string(rr.name),
		rr.rtype,
		rr.class,
		rr.ttl,
		rr.length,
		rr.rdata,
	)
}

func newResourceRecord(b []byte) (*resourceRecord, []byte) {
	rr := &resourceRecord{}
	rr.rtype, b = read16(b)
	rr.class, b = read16(b)
	rr.ttl, b = read32(b)
	rr.length, b = read16(b)
	rr.rdata, b = read32(b)
	return rr, b
}
