package dns

import (
	"encoding/binary"
	"fmt"

	"github.com/davecgh/go-spew/spew"
)

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
type Msg struct {
	reader *msgReader
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
	header   header
	question question
	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
	resource resourceRecord
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

// NewMessage provides a standard way to reading the msg
func NewMessage(b []byte) *Msg {
	msg := &Msg{reader: newMsgReader(b)}
	msg.parseHeader()
	question := msg.parseQuestion()
	msg.parseRR()
	msg.resource.name = question.qname

	fmt.Println("resulting length:", len(b), msg.resource.name)
	return msg
}

func (m Msg) Write() []byte {
	bb := []byte{}
	bb = append(bb, m.header.write()...)
	bb = append(bb, m.question.write()...)
	bb = append(bb, m.resource.write()...)
	println("---SEND---")
	spew.Dump(bb)
	return bb
}

func (m *Msg) parseRR() {
	m.resource.rtype = m.reader.read16()
	m.resource.class = m.reader.read16()
	m.resource.ttl = m.reader.read32()
	m.resource.length = m.reader.read16()
	m.resource.rdata = m.reader.read32()
}

// parseHeader provides a standard way to reading the msg header
func (m *Msg) parseHeader() {
	println("---HEADER---")
	spew.Dump(m.reader.buff)

	println(m.reader.pos, len(m.reader.buff))
	m.header.id = m.reader.read16()
	println(m.reader.pos, len(m.reader.buff))
	m.header.parseQINFO(m.reader.read16())
	println(m.reader.pos, len(m.reader.buff))
	m.header.questions = m.reader.read16()
	println(m.reader.pos, len(m.reader.buff))
	m.header.answers = m.reader.read16()
	println(m.reader.pos, len(m.reader.buff))
	m.header.authorities = m.reader.read16()
	println(m.reader.pos)
	m.header.additionals = m.reader.read16()
	println(m.reader.pos)
}

func (m *Msg) parseQuestion() question {
	q := question{}
	q.qname = m.readQName()
	q.qtype = m.reader.read16()
	q.qclass = m.reader.read16()
	return q
}

// right now I do not support more than 1 RFC 1035 label
func (m *Msg) readQName() string {
	// this is the initial length

	labelLen := uint8(m.reader.buff[m.reader.pos])
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
