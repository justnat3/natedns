package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
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

var (
	ErrorBufferTooShortForLabel = errors.New("read-qname: buffer too short for label len")
	ErrorMaxJumpsReached        = errors.New("read-qname: max jumps reached")
	ErrorLabelTooLong           = errors.New("read-qname: label has illegal length")
	ErrorLabelHasEmpty          = errors.New("read-qname: label is empty")
)

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
type Msg struct {
	took time.Duration
	rw   *MsgRW

	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
	Header

	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	Question

	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
	// FIXME: should probably do something different than hold potentially nil pointers
	Records []Record
}

// ParseMsg provides a standard way to reading the msg
func ParseMsg(b []byte) *Msg {
	t := time.Now()
	msg := &Msg{rw: newMsgReader(b)}
	msg.parseHeader()

	// TODO(nate): should be able to parse more messages
	msg.parseQuestion()

	for range msg.Answers {
		msg.readDnsRecord()
	}

	for range msg.Authorities {
		msg.readDnsRecord()
	}

	for range msg.Additional {
		msg.readDnsRecord()
	}

	msg.took = time.Since(t)
	return msg
}

// NewMessage returns a valid pointer to a new Msg
// TODO(nate): for right now we only support one question
// I dont support inverse queries, as they are purely optional
func NewMessage(q Question) *Msg {
	rw := MsgRW{buff: make([]byte, 0, 512)}
	_ = Msg{rw: &rw, Question: q}
	return nil
}

func (q Question) Bytes() []byte {
	dbuff, err := DomainToLabel(q.Domain)

	// FIXME(nate): do not panic
	if err != nil {
		panic(err)
	}

	var out []byte
	out = append(out, dbuff...)
	out = append(out, uint8(0))
	out = append(out, uint8(q.Type))
	out = append(out, uint8(0))
	out = append(out, uint8(q.Class))

	return out

}

func (qc QueryClass) Bytes() []byte {
	var out []byte
	out = append(out, uint8(qc>>8))
	out = append(out, uint8(qc&0xff))
	return out
}

func (m Msg) Bytes() []byte {
	bb := []byte{}
	bb = append(bb, m.Header.Bytes()...)
	bb = append(bb, m.Question.Bytes()...)
	// j := make([]byte, 512-len(bb))
	// bb = append(bb, j...)
	return bb
}

// 0000   d5 7e 81 80 00 01 00 06 00 00 00 01 06 67 6f 6f   .~...........goo
// 0010   67 6c 65 03 63 6f 6d 00 00 01 00 01 c0 0c 00 01   gle.com.........
// 0020   00 01 00 00 01 07 00 04 8e fa 71 8b c0 0c 00 01   ..........q.....
// 0030   00 01 00 00 01 07 00 04 8e fa 71 71 c0 0c 00 01   ..........qq....
// 0040   00 01 00 00 01 07 00 04 8e fa 71 65 c0 0c 00 01   ..........qe....
// 0050   00 01 00 00 01 07 00 04 8e fa 71 66 c0 0c 00 01   ..........qf....
// 0060   00 01 00 00 01 07 00 04 8e fa 71 64 c0 0c 00 01   ..........qd....
// 0070   00 01 00 00 01 07 00 04 8e fa 71 8a 00 00 29 02   ..........q...).
// 0080   00 00 00 00 00 00 00                              .......

func (m *Msg) readDnsRecord() {
	var domain string
	if m.rw.current() == 0 {
		domain = "<Root>"
		m.rw.advance()
	} else {
		domain = m.readLabelSet()
	}

	_qtype := m.rw.read16()
	switch QueryType(_qtype) {
	case A:
		_class := m.rw.read16() // class
		ttl := m.rw.read32Signed()
		len := m.rw.read16()

		ip := m.rw.readAddr()
		record := newRecord(QueryClass(_class), QueryType(_qtype), ttl, &len, WithAddr(*ip), WithDomain(domain))
		m.Records = append(m.Records, record)

	// EDNS feature
	case Opt:
		// skip
		m.rw.read16()
		m.rw.read16()
		m.rw.read16()

		len := m.rw.read16()
		m.rw.advanceN(int(len))

		m.Records = append(m.Records, newRecord(0, Opt, 0, &len))

	case Soa:
		_ = m.rw.read16() // class
		_ = m.rw.read32Signed()
		len := m.rw.read16()
		m.rw.advanceN(int(len))
		return
		// record := Record{Class: QueryClass(_class), Type: QueryType(_qtype)}
		// spew.Dump(ttl, len)
		// m.rw.ViewWindow(m.rw.pos, m.rw.pos+int(len), -1)
		// record.SOAR = &SOAR{}
		// record.SOAR.MName = m.readLabelSet()
		// record.SOAR.RName = m.readLabelSet()
		// record.SOAR.Serial = m.rw.read32()
		// record.SOAR.Refresh = m.rw.read32()
		// record.SOAR.Retry = m.rw.read32()
		// record.SOAR.Expire = m.rw.read32()
		// record.SOAR.Min = m.rw.read32()
		// spew.Dump(record.SOAR)

	default:
		_class := m.rw.read16() // class
		println("type:", QueryClass(_class).String(), _class)
		ttl := m.rw.read32Signed()
		len := m.rw.read16()

		m.rw.advanceN(int(len))
		record := newRecord(QueryClass(_class), QueryType(_qtype), ttl, &len, WithDomain(domain))
		m.Records = append(m.Records, record)
	}
	return
}

func (m Msg) Print() {

	println(";<<>> natedns (linux) <<>>" + m.Question.Domain)
	println(";;Got answer:", "; id:", m.ID)
	println()
	println(";;->>Header<<- opcode:", m.OpCode.String(), "status:", m.RCode.String())
	println(";;flags:", m.RD, m.RA)
	println(";Query:", m.QR)
	println()
	println(";Questions:", m.Questions)
	println(";Answer:", m.Answers)
	println(";Authority:", m.Authorities)
	println(";Additional:", m.Additional)
	println()
	println(";;Question Section:")
	for _, r := range m.Records {
		println(r.Domain, r.Type.String(), r.Class.String(), r.Addr.String())
	}
	println()
	println(";;Query Time:", m.took.String())
	println(";Server: 127.0.0.1 (UDP)")
}

// parseHeader provides a standard way to reading the msg header
func (m *Msg) parseHeader() {
	m.Header.ID = m.rw.read16()
	m.Header.parseHdrFlags(m.rw.read16())
	m.Header.Questions = m.rw.read16()
	m.Header.Answers = m.rw.read16()
	m.Header.Authorities = m.rw.read16()
	m.Header.Additional = m.rw.read16()
}

func (m *Msg) parseQuestion() {
	q := Question{}
	q.Domain = m.readLabelSet()
	println("pos", m.rw.pos)
	q.Type = QueryType(m.rw.read16())
	q.Class = QueryClass(m.rw.read16())
	m.Question = q
}

// right now I do not support more than 1 RFC 1035 label
func (m *Msg) readLabelSet() string {
	if len(m.rw.buff) < 1 {
		panic(ErrorBufferTooShortForLabel)
	}

	jmps := 0
	j := false
	pos := m.rw.pos
	str := "."
	for {
		labelLen := uint8(m.rw.buff[pos])
		if (labelLen & 0xc0) == 0xc0 {
			if !j {
				m.rw.advanceN(2)
			}

			pos = int(((uint16(labelLen) ^ 0xc0) << 8) | uint16(m.rw.buff[pos+1]))
			// m.reader.window(4)

			j = true
			jmps++

			continue
		}
		pos++

		if jmps > 10 {
			panic(ErrorMaxJumpsReached)
		}

		// if labelLen > 63 && jmps < 1 {
		// 	panic(ErrorLabelTooLong)
		// }

		if m.rw.buff[pos] == 0 {
			break
		}

		str += string(m.rw.buff[pos : pos+int(labelLen)])
		str += string('.')
		pos += int(labelLen)
	}

	if !j {
		m.rw.jumpTo(pos)
	}

	return str
}

func printbin(i ...uint16) {
	for _, i := range i {
		print(fmt.Sprintf("%b ", i))
	}
	println()
}

// Resource Record
type Record struct {
	Type   QueryType
	Class  QueryClass
	TTL    int32
	Addr   net.IP
	Len    *uint16
	Domain string
	*SOAR
}

type SOAR struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Min     uint32
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

func newRecord(_class QueryClass, _type QueryType, ttl int32, len *uint16, opts ...recordOption) Record {
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
