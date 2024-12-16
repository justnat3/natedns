package dns

import (
	"encoding/binary"
	"fmt"

	"github.com/davecgh/go-spew/spew"
)

type Msg struct {
	reader   *MsgReader
	header   header
	question question
	resource resourceRecord
}

type MsgReader struct {
	pos     int
	buff    []byte
	bufflen int
}

func newMsgReader(b []byte) *MsgReader {
	return &MsgReader{buff: b, bufflen: len(b)}
}

func (m *Msg) parseHeader() {
	println("---HEADER---")
	spew.Dump(m.reader.buff)

	m.header.id = m.reader.read16()
	m.header.parseQINFO(m.reader.read16())
	m.header.questions = m.reader.read16()
	m.header.answers = m.reader.read16()
	m.header.authorities = m.reader.read16()
	m.header.additionals = m.reader.read16()

}

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

func (mr *MsgReader) read16() uint16 {
	out := binary.BigEndian.Uint16(mr.buff[mr.pos:2])
	mr.pos += 2
	return out
}

func (mr *MsgReader) read32() uint32 {
	mr.pos += 4
	return binary.BigEndian.Uint32(mr.buff[mr.pos:4])
}
