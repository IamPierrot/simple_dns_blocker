package dns

import (
	"encoding/binary"
	"fmt"
	"net"
)

func extractQuestion(req []byte) ([]byte, error) {
	if len(req) < 12 {
		return nil, fmt.Errorf("invalid dns packet")
	}

	pos := 12

	for {
		if pos >= len(req) {
			return nil, fmt.Errorf("invalid qname")
		}

		l := int(req[pos])
		pos++

		if l == 0 {
			break
		}

		// compression pointer
		if l&0xC0 == 0xC0 {
			if pos >= len(req) {
				return nil, fmt.Errorf("invalid compression pointer")
			}

			pos++
			break
		}

		pos += l

		if pos > len(req) {
			return nil, fmt.Errorf("invalid label length")
		}
	}

	// QTYPE + QCLASS
	pos += 4

	if pos > len(req) {
		return nil, fmt.Errorf("invalid question")
	}

	return req[12:pos], nil
}

func buildFlags(req []byte, rcode byte) (byte, byte) {
	flags := binary.BigEndian.Uint16(req[2:4])

	rd := flags & 0x0100

	respFlags := uint16(0x8000) // QR=1
	respFlags |= rd             // copy RD
	respFlags |= uint16(rcode)

	return byte(respFlags >> 8), byte(respFlags)
}

func BuildNXDomain(req []byte) []byte {
	question, err := extractQuestion(req)
	if err != nil {
		return nil
	}

	resp := make([]byte, 0, 512)

	resp = append(resp, req[0], req[1])

	f1, f2 := buildFlags(req, 3)
	resp = append(resp, f1, f2)

	resp = append(resp, req[4], req[5])

	// ANCOUNT
	resp = append(resp, 0x00, 0x00)

	// NSCOUNT
	resp = append(resp, 0x00, 0x00)

	// ARCOUNT
	resp = append(resp, 0x00, 0x00)

	resp = append(resp, question...)

	return resp
}

func BuildErrorResponse(req []byte, rcode byte) []byte {
	question, err := extractQuestion(req)
	if err != nil {
		return nil
	}

	resp := make([]byte, 0, 512)

	resp = append(resp, req[0], req[1])

	f1, f2 := buildFlags(req, rcode)
	resp = append(resp, f1, f2)

	resp = append(resp, req[4], req[5])

	resp = append(resp,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	)

	resp = append(resp, question...)

	return resp
}

func BuildARecord(req []byte, ip net.IP) []byte {
	question, err := extractQuestion(req)
	if err != nil {
		return nil
	}

	resp := make([]byte, 0, 512)

	resp = append(resp, req[0], req[1])

	f1, f2 := buildFlags(req, 0)
	resp = append(resp, f1, f2)

	resp = append(resp, req[4], req[5])

	// ANCOUNT = 1
	resp = append(resp, 0x00, 0x01)

	// NSCOUNT = 0
	resp = append(resp, 0x00, 0x00)

	// ARCOUNT = 0
	resp = append(resp, 0x00, 0x00)

	resp = append(resp, question...)

	resp = append(resp,
		0xC0, 0x0C, // NAME pointer
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3C, // TTL
		0x00, 0x04, // RDLENGTH
	)

	ipv4 := ip.To4()
	if ipv4 == nil {
		ipv4 = net.IPv4zero
	}

	resp = append(resp, ipv4...)

	return resp
}

func BuildAAAARecord(req []byte, ip net.IP) []byte {
	question, err := extractQuestion(req)
	if err != nil {
		return nil
	}

	resp := make([]byte, 0, 512)

	resp = append(resp, req[0], req[1])

	f1, f2 := buildFlags(req, 0)
	resp = append(resp, f1, f2)

	resp = append(resp, req[4], req[5])

	// ANCOUNT = 1
	resp = append(resp, 0x00, 0x01)

	// NSCOUNT = 0
	resp = append(resp, 0x00, 0x00)

	// ARCOUNT = 0
	resp = append(resp, 0x00, 0x00)

	resp = append(resp, question...)

	resp = append(resp,
		0xC0, 0x0C, // NAME pointer
		0x00, 0x1C, // TYPE AAAA
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3C, // TTL
		0x00, 0x10, // RDLENGTH
	)

	ipv6 := ip.To16()
	if ipv6 == nil {
		ipv6 = make([]byte, 16)
	}

	resp = append(resp, ipv6...)

	return resp
}
