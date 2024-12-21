package dns

import (
	"errors"
	"fmt"
	"time"
)

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
	header
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	question
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3

	// FIXME: should probably do something different than hold potentially nil pointers
	Records []Record
}

// NewMessage provides a standard way to reading the msg
func NewMessage(b []byte) *Msg {
	t := time.Now()
	msg := &Msg{rw: newMsgReader(b)}
	msg.parseHeader()

	// TODO(nate): should be able to parse more messages
	msg.parseQuestion()

	for range msg.answers {
		msg.parseDNSRecord()
	}

	for range msg.authorities {
		msg.parseDNSRecord()
	}

	for range msg.additional {
		msg.parseDNSRecord()
	}

	msg.took = time.Since(t)
	return msg
}

func (m Msg) Write() []byte {
	bb := []byte{}
	bb = append(bb, m.header.write()...)
	bb = append(bb, m.question.write()...)
	return bb
}
func printbin(i ...uint16) {
	for _, i := range i {
		print(fmt.Sprintf("%b ", i))
	}
	println()
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
	var domain string
	if m.rw.current() == 0 {
		domain = "<Root>"
		m.rw.advance()
	} else {
		domain = m.readQName()
	}

	_qtype := m.rw.read16()
	switch qtype(_qtype) {
	case A:
		_class := m.rw.read16() // class
		ttl := m.rw.read32()
		len := m.rw.read16()

		ip := m.rw.readIPAddr()
		record := newRecord(class(_class), qtype(_qtype), ttl, &len, WithAddr(*ip), WithDomain(domain))
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

	default:
		_class := m.rw.read16() // class
		println("type:", class(_class).String(), _class)
		ttl := m.rw.read32()
		len := m.rw.read16()

		m.rw.advanceN(int(len))
		record := newRecord(class(_class), qtype(_qtype), ttl, &len, WithDomain(domain))
		m.Records = append(m.Records, record)
	}
	return
}

func (m Msg) Print() {

	println(";<<>> natedns (linux) <<>>" + m.question.qname)
	println(";;Got answer:", "; id:", m.id)
	println()
	println(";;->>Header<<- opcode:", m.opcode.String(), "status:", m.rcode.String())
	println(";;flags:", m.rd.String(), m.ra.String())
	println(";Query:", m.qr.String())
	println()
	println(";Questions:", m.questions)
	println(";Answer:", m.answers)
	println(";Authority:", m.authorities)
	println(";Additional:", m.additional)
	println()
	println(";;Question Section:")
	for _, r := range m.Records {
		println(r.domain, r._type.String(), r._class.String(), r.addr.String())
	}
	println()
	println(";;Query Time:", m.took.String())
	println(";Server: 127.0.0.1 (UDP)")
}

// parseHeader provides a standard way to reading the msg header
func (m *Msg) parseHeader() {
	m.header.id = m.rw.read16()
	m.header.parseHdrFlags(m.rw.read16())
	m.header.questions = m.rw.read16()
	m.header.answers = m.rw.read16()
	m.header.authorities = m.rw.read16()
	m.header.additional = m.rw.read16()
}

func (m *Msg) parseQuestion() {
	q := question{}
	q.qname = m.readQName()
	q.qtype = qtype(m.rw.read16())
	q.qclass = class(m.rw.read16())
}

// right now I do not support more than 1 RFC 1035 label
func (m *Msg) readQName() string {
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
