package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
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

// a bit field that tells us if its a query or response
type qr = int

const (
	Query qr = iota + 1
	Response
	qrNone
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
	id      uint16
	qinfo   uint16
	qdcount uint16
	ancount uint16
	nscount uint16
	arcount uint16
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

func (hdr header) qr() uint16 {
	return (hdr.qinfo & QrMask) >> 15
}

func (hdr header) aa() uint16 {
	return (hdr.qinfo & AAMask) >> 10
}

func (hdr header) opcode() uint16 {
	return (hdr.qinfo & OPCodeMask) >> 11
}

func (hdr header) tc() uint16 {
	return (hdr.qinfo & TCMask) >> 9
}

func (hdr header) rd() uint16 {
	return (hdr.qinfo & RDMask) >> 8
}

func (hdr header) ra() uint16 {
	return (hdr.qinfo & RAMask) >> 7
}

func (hdr header) z() uint16 {
	return (hdr.qinfo & ZMask) >> 6
}

func (hdr header) rcode() uint16 {
	return (hdr.qinfo & RCodeMask)
}

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
		"id:%d\nqr:%d\nopcode:%d\naa:%d\ntc:%d\nrd:%d\nra:%d\nz:%d\nrcode:%d\nqd:%d\nan:%d\nns:%d\nar:%d"
	if withNewLines {
		return fmt.Sprintf(
			newline,
			hdr.id,
			hdr.qr(),
			hdr.opcode(),
			hdr.aa(),
			hdr.tc(),
			hdr.rd(),
			hdr.ra(),
			hdr.z(),
			hdr.rcode(),
			hdr.qdcount,
			hdr.ancount,
			hdr.nscount,
			hdr.arcount,
		)
	}
	return fmt.Sprintf(
		nonewline,
		hdr.id,
		hdr.qr(),
		hdr.opcode(),
		hdr.aa(),
		hdr.tc(),
		hdr.rd(),
		hdr.ra(),
		hdr.z(),
		hdr.rcode(),
		hdr.qdcount,
		hdr.ancount,
		hdr.nscount,
		hdr.arcount,
	)
}

func read16(b []byte) (uint16, []byte) {
	return binary.BigEndian.Uint16(b[0:2]), b[2:]
}

func NewHeader(b []byte) (*header, []byte) {
	hdr := &header{}
	hdr.id, b = read16(b)
	hdr.qinfo, b = read16(b)
	hdr.qdcount, b = read16(b)
	hdr.ancount, b = read16(b)
	hdr.nscount, b = read16(b)
	hdr.arcount, b = read16(b)
	return hdr, b
}

type question struct {
	qname  []byte
	qtype  uint16
	qclass uint16
}

func NewQuestion(b []byte) (*question, []byte) {
	q := &question{}
	q.qname = b[0:11]
	q.qtype, b = read16(b[12:])
	q.qclass, b = read16(b)
	return q, b
}

func (q question) String() string {
	return fmt.Sprintf(
		"question: %s\nqtype: %d\n, qclass: %d",
		string(q.qname),
		q.qtype,
		q.qclass,
	)
}

type Message struct {
	hdr header
	q   question
}

func (m Message) String() string {
	return m.hdr.String(true) + "\n" + m.q.String()
}

func NewMessage(b []byte) *Message {
	hdr, b := NewHeader(b)
	q, b := NewQuestion(b)
	m := &Message{hdr: *hdr, q: *q}
	return m
}

type answer struct{}
type authority struct{}
type additional struct{}
