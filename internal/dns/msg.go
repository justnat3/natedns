package dns

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	_type  qtype
	_class class
	ttl    uint32
	addr   net.IP
	len    *uint16
	domain string
}

// msgReader defines a way to read the DNS Message as a buffer
type msgReader struct {
	pos     int    // position in the buffer
	buff    []byte // buffer of the message in question
	bufflen int    // len of the buffer read once
}

func (m *msgReader) current() uint8 {
	return m.buff[m.pos]
}

func (m *msgReader) advance() {
	m.pos++
}

func (m *msgReader) advanceN(amount int) {
	if m.pos+amount > len(m.buff) {
		panic("tried to read too far")
	}
	m.pos += amount
}

func (m *msgReader) window(w int) {
	if m.pos+w > len(m.buff) {
		println("UP_TO-window_of", m.pos, "@", hex.EncodeToString(m.buff[w-m.pos:m.pos]))
		return
	}

	if m.pos-w < 0 {
		println("DOWN_TO-window_of", m.pos, "@", hex.EncodeToString(m.buff[m.pos:m.pos]))
		return
	}

	println("window_of", m.pos, "@", hex.EncodeToString(m.buff[m.pos-w:m.pos+w]))
}

func (m *msgReader) jumpTo(pos int) {
	if pos > len(m.buff) {
		panic("oopsies jumped too far")
	}

	m.pos = pos
	// m.window(4)
}

// newMsgReader returns a msgReader with the buff and len intialized
func newMsgReader(b []byte) *msgReader {
	return &msgReader{buff: b, bufflen: len(b)}
}

func (m *msgReader) read16() uint16 {
	out := binary.BigEndian.Uint16(m.buff[m.pos : m.pos+2])
	m.advanceN(2)
	return out
}

func (m *msgReader) read32() uint32 {
	out := binary.BigEndian.Uint32(m.buff[m.pos : m.pos+4])
	m.advanceN(4)
	return out
}

func (m *msgReader) read64() uint64 {
	out := binary.BigEndian.Uint64(m.buff[m.pos : m.pos+8])
	m.advanceN(8)
	return out
}

// NewMessage provides a standard way to reading the msg
func NewMessage(b []byte) *Msg {
	t := time.Now()
	msg := &Msg{reader: newMsgReader(b)}
	msg.parseHeader()
	msg.parseQuestion()

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
		buff = append(buff, m.reader.current())
		m.reader.advance()
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

// 0000   d5 7e 81 80 00 01 00 06 00 00 00 01 06 67 6f 6f   .~...........goo
// 0010   67 6c 65 03 63 6f 6d 00 00 01 00 01 c0 0c 00 01   gle.com.........
// 0020   00 01 00 00 01 07 00 04 8e fa 71 8b c0 0c 00 01   ..........q.....
// 0030   00 01 00 00 01 07 00 04 8e fa 71 71 c0 0c 00 01   ..........qq....
// 0040   00 01 00 00 01 07 00 04 8e fa 71 65 c0 0c 00 01   ..........qe....
// 0050   00 01 00 00 01 07 00 04 8e fa 71 66 c0 0c 00 01   ..........qf....
// 0060   00 01 00 00 01 07 00 04 8e fa 71 64 c0 0c 00 01   ..........qd....
// 0070   00 01 00 00 01 07 00 04 8e fa 71 8a 00 00 29 02   ..........q...).
// 0080   00 00 00 00 00 00 00                              .......

func (m *Msg) parseDNSRecord() {
	domain := m.readQName()
	_qtype := m.reader.read16()
	_class := m.reader.read16() // class
	ttl := m.reader.read32()
	len := m.reader.read16()
	switch qtype(_qtype) {
	case A:
		ip := m.readIPAddr()
		record := newRecord(class(_class), qtype(_qtype), ttl, &len, WithAddr(*ip), WithDomain(domain))
		m.Records = append(m.Records, record)
	default:
		m.reader.advanceN(int(len))
		record := newRecord(class(_class), qtype(_qtype), ttl, &len, WithDomain(domain))
		m.Records = append(m.Records, record)
	}
	return
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

func (m Msg) Print() {

	if len(m.Records) < 1 {
		return
	}
	println(";<<>> natedns (linux) <<>>" + m.Records[0].domain)
	println(";;Got answer:", "; id:", m.id)
	println()
	println(";;->>Header<<- opcode:", m.opcode.String(), "status:", m.reponseCode.String())
	println(";;flags:", m.recursionDesired.String(), m.recursionAvaiable.String())
	println(";Query:", m.queryReponse.String())
	println()
	println(";Questions:", m.questions)
	println(";Answer:", m.answers)
	println(";Authority:", m.nsRecs)
	println(";Additional:", m.addRecs)
	println()
	println(";;Question Section:")
	for _, r := range m.Records {
		println(r.domain, r._type.String(), r._class.String(), r.addr.String())
	}
	println()
	println(";;Query Time:", m.took.String())
	println(";Server: 127.0.0.1 (UDP)")
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
	q.qclass = class(m.reader.read16())
}

var (
	ErrorBufferTooShortForLabel = errors.New("read-qname: buffer too short for label len")
	ErrorMaxJumpsReached        = errors.New("read-qname: max jumps reached")
	ErrorLabelTooLong           = errors.New("read-qname: label has illegal length")
	ErrorLabelHasEmpty          = errors.New("read-qname: label is empty")
)

// right now I do not support more than 1 RFC 1035 label
func (m *Msg) readQName() string {
	if len(m.reader.buff) < 1 {
		panic(ErrorBufferTooShortForLabel)
	}

	jmps := 0
	j := false
	pos := m.reader.pos
	str := "."
	for {
		labelLen := uint8(m.reader.buff[pos])
		if (labelLen & 0xc0) == 0xc0 {
			if !j {
				m.reader.advanceN(2)
			}

			pos = int(((uint16(labelLen) ^ 0xc0) << 8) | uint16(m.reader.buff[pos+1]))
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

		if m.reader.buff[pos] == 0 {
			break
		}

		str += string(m.reader.buff[pos : pos+int(labelLen)])
		str += string('.')
		pos += int(labelLen)
	}

	if !j {
		m.reader.jumpTo(pos)
	}
	return str
}
