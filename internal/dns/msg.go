package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
type Msg struct {
	took   time.Duration
	reader *msgReader
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
	header
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	question
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3

	// FIXME: should probably do something different than hold potentially nil pointers
	Records []Record
}

type Record struct {
	// NOTE(nate): this includes A records :)
	_type  qtype
	_class class
	ttl    uint32
	addr   *net.IP
	len    *uint16
	domain string
}

// msgReader defines a way to read the DNS Message as a buffer
type msgReader struct {
	pos     int    // position in the buffer
	buff    []byte // buffer of the message in question
	bufflen int    // len of the buffer read once
}

// newMsgReader returns a msgReader with the buff and len intialized
func newMsgReader(b []byte) *msgReader {
	return &msgReader{buff: b, bufflen: len(b)}
}

func (mr *msgReader) read16() uint16 {
	out := binary.BigEndian.Uint16(mr.buff[mr.pos : mr.pos+2])
	mr.pos += 2
	return out
}

func (mr *msgReader) read32() uint32 {
	out := binary.BigEndian.Uint32(mr.buff[mr.pos : mr.pos+4])
	mr.pos += 4
	return out
}

func (mr *msgReader) read64() uint64 {
	out := binary.BigEndian.Uint64(mr.buff[mr.pos : mr.pos+8])
	mr.pos += 8
	return out
}

// NewMessage provides a standard way to reading the msg
func NewMessage(b []byte) *Msg {
	t := time.Now()
	msg := &Msg{reader: newMsgReader(b)}
	msg.parseHeader()
	msg.parseQuestion()
	domain := msg.readQName()

	print(domain)
	for range msg.answers {
		msg.parseDNSRecord()
	}

	msg.took = time.Since(t)
	msg.Print()
	return msg
}

func (m Msg) Write() []byte {
	bb := []byte{}
	bb = append(bb, m.header.write()...)
	bb = append(bb, m.question.write()...)
	return bb
}

func (m *Msg) readTo(len uint16) []byte {
	buff := make([]byte, len)

	_len := int(len) // where is size_t when you need it :\

	if m.reader.pos+_len > m.reader.bufflen {
		panic("dns-readto: the buffer is too short dumby")
	}

	for m.reader.pos >= m.reader.pos+_len {
		buff = append(buff, m.reader.buff[m.reader.pos])
		m.reader.pos++
	}

	return buff
}

func printbin(i ...uint16) {
	for _, i := range i {
		print(fmt.Sprintf("%b ", i))
	}
	println()
}

func (m *Msg) readIPAddr() *net.IP {
	addr := m.reader.read32()
	ip := net.IPv4(
		uint8((addr>>24)&0xff),
		uint8((addr>>16)&0xff),
		uint8((addr>>8)&0xff),
		uint8((addr>>0)&0xff),
	)
	return &ip
}

func (m *Msg) parseDNSRecord() {
	_qtype := m.reader.read16()
	_class := m.reader.read16() // class
	ttl := m.reader.read32()
	len := m.reader.read16()

	switch qtype(_qtype) {
	case A:
		ip := m.readIPAddr()
		record := newRecord(class(_class), A, ttl, &len, WithAddr(ip))
		m.Records = append(m.Records, record)

	case Ptr:
		// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
		offset := m.reader.read16()
		ip := m.readIPAddr()

		offset = offset & (1 << 2)
		if offset < 1 {
			return
		}

		old := m.reader.pos
		m.reader.pos = int(offset)

		_ = m.reader.read64()

		domain := m.readQName()
		m.reader.pos = old

		record := newRecord(class(_class), Ptr, ttl, &len, WithAddr(ip), WithDomain(domain))
		m.Records = append(m.Records, record)

		return
	}
}

type recordOption func(*Record)

func WithAddr(ip *net.IP) recordOption {
	return func(r *Record) {
		r.addr = ip
	}
}

func WithDomain(s string) recordOption {
	return func(r *Record) {
		r.domain = s
	}
}

func (m Msg) Print() {

	if len(m.Records) < 1 {
		return
	}
	println("; <<>> natedns (linux) <<>>" + m.Records[0].domain)
	println(";; Got answer:")
	println(";; ->>Header<<- opcode:", m.opcode.String(), "status:", m.reponseCode.String(), "id:", m.id)
	println(";; flags:", m.queryReponse.String(), m.recursionDesired.String(), m.recursionAvaiable.String(), "; Query:", m.queryReponse.String())
	println("Answer:", m.answers, "Authority:", m.nsRecs, "Additional:", m.addRecs)

	println(";; Question Section:")
	for _, r := range m.Records {
		println(r.domain, r._type.String(), r._class.String(), r.addr.String())
	}

	println(";; Query Time:", m.took.String())
	println(";; Server: 127.0.0.1 (UDP)")
}
func newRecord(_class class, _type qtype, ttl uint32, len *uint16, opts ...recordOption) Record {
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

// parseHeader provides a standard way to reading the msg header
func (m *Msg) parseHeader() {
	m.header.id = m.reader.read16()
	m.header.parseHdrFlags(m.reader.read16())
	m.header.questions = m.reader.read16()
	m.header.answers = m.reader.read16()
	m.header.nsRecs = m.reader.read16()
	m.header.addRecs = m.reader.read16()
}

func (m *Msg) parseQuestion() {
	q := question{}
	q.qname = m.readQName()
	q.qtype = qtype(m.reader.read16())
	q.qclass = m.reader.read16()
}

// right now I do not support more than 1 RFC 1035 label
func (m *Msg) readQName() string {
	// this is the initial length

	labelLen := uint8(m.reader.buff[m.reader.pos])

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

		str += string(m.reader.buff[m.reader.pos])
		if int(labelLen) == 0 {
			str += string('.')
			labelLen = uint8(m.reader.buff[m.reader.pos])
			m.reader.pos++
		}

		labelLen--
		m.reader.pos++
	}

	if len(str) < 1 {
		panic(ErrorInvalidQNameLength)
	}

	return str
}
