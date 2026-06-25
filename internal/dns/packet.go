package dns

import (
	"fmt"
	"strings"
)

type BytePacketBuffer struct {
	buf []byte
	pos int
}

func NewBytePacketBuffer(data []byte) *BytePacketBuffer {
	return &BytePacketBuffer{
		buf: data,
		pos: 0,
	}
}

func (b *BytePacketBuffer) Read() (byte, error) {
	if b.pos >= len(b.buf) {
		return 0, fmt.Errorf("end of buffer")
	}

	v := b.buf[b.pos]
	b.pos++

	return v, nil
}

func (b *BytePacketBuffer) ReadChunk(length int) ([]byte, error) {
	if b.pos+length > len(b.buf) {
		return nil, fmt.Errorf("end of buffer")
	}

	res := b.buf[b.pos : b.pos+length]
	b.pos += length

	return res, nil
}

func (b *BytePacketBuffer) ReadQName() (string, error) {
	var labels []string

	for {
		l, err := b.Read()
		if err != nil {
			return "", err
		}

		if l == 0 {
			break
		}

		chunk, err := b.ReadChunk(int(l))
		if err != nil {
			return "", err
		}

		labels = append(labels, string(chunk))
	}

	return strings.Join(labels, "."), nil
}
