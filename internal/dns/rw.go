package dns

import (
	"encoding/binary"
	"encoding/hex"
	"net"
)

/*
 * TODO(nate): These operations do not take into account overflow :)
 */

// MsgRW defines a way to read the DNS Message as a buffer
type MsgRW struct {
	pos     int    // position in the buffer
	buff    []byte // buffer of the message in question
	bufflen int    // len of the buffer read once
}

func (rw *MsgRW) readAddr() *net.IP {
	addr := rw.read32()
	ip := net.IPv4(
		uint8((addr>>24)&0xff),
		uint8((addr>>16)&0xff),
		uint8((addr>>8)&0xff),
		uint8((addr>>0)&0xff),
	)
	return &ip
}

func (rw *MsgRW) readTo(len uint16) []byte {
	buff := make([]byte, len)

	_len := int(len) // where is size_t when you need it :\

	if rw.pos+_len > rw.bufflen {
		panic("dns-readto: the buffer is too short dumby")
	}

	for rw.pos >= rw.
		pos+_len {
		buff = append(buff, rw.current())
		rw.advance()
	}

	return buff
}

func (rw *MsgRW) write16(n uint16) {
	binary.BigEndian.PutUint16(rw.buff, n)
	rw.advanceN(2)
}

func (rw *MsgRW) write32(n uint32) {
	binary.BigEndian.PutUint32(rw.buff, n)
	rw.advanceN(4)
}

func (rw *MsgRW) write64(n uint64) {
	binary.BigEndian.PutUint64(rw.buff, n)
	rw.advanceN(8)
}

func (rw *MsgRW) clear() {
	clear(rw.buff)
	rw.pos = 0
}
func (m *MsgRW) current() uint8 {
	return m.buff[m.pos]
}

func (m *MsgRW) advance() {
	m.pos++
}

func (m *MsgRW) advanceN(amount int) {
	if m.pos+amount > len(m.buff) {
		panic("tried to read too far")
	}
	m.pos += amount
}

func (m *MsgRW) window(w int, ahead bool) {
	if m.pos+w > len(m.buff) {
		println("UP_TO-window_of", m.pos, "@", hex.EncodeToString(m.buff[w-m.pos:m.pos]))
		return
	}

	if m.pos-w < 0 {
		println("DOWN_TO-window_of", m.pos, "@", hex.EncodeToString(m.buff[m.pos:m.pos]))
		return
	}

	if ahead {
		println("window_of", m.pos, "@", hex.EncodeToString(m.buff[m.pos:m.pos+w]))
		return
	}
	println("window_of", m.pos, "@", hex.EncodeToString(m.buff[m.pos-w:m.pos+w]))
}

func (m *MsgRW) jumpTo(pos int) {
	if pos > len(m.buff) {
		panic("oopsies jumped too far")
	}

	m.pos = pos
}

// newMsgReader returns a msgReader with the buff and len intialized
func newMsgReader(b []byte) *MsgRW {
	return &MsgRW{buff: b, bufflen: len(b)}
}

func (m *MsgRW) read16() uint16 {
	out := binary.BigEndian.Uint16(m.buff[m.pos : m.pos+2])
	m.advanceN(2)
	return out
}

func (m *MsgRW) read32() uint32 {
	out := binary.BigEndian.Uint32(m.buff[m.pos : m.pos+4])
	m.advanceN(4)
	return out
}

func (m *MsgRW) read64() uint64 {
	out := binary.BigEndian.Uint64(m.buff[m.pos : m.pos+8])
	m.advanceN(8)
	return out
}
