package dns

import (
	"net"
)

// BuildNXDomain trả về lỗi Non-Existent Domain (RCODE=3)
func BuildNXDomain(req []byte) []byte {
	resp := make([]byte, 0, 512)

	// Transaction ID
	resp = append(resp, req[0], req[1])

	// Flags: QR=1 (Response), Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=3 (NXDOMAIN)
	resp = append(resp, 0x81, 0x83)

	// QDCOUNT
	resp = append(resp, req[4], req[5])

	// ANCOUNT, NSCOUNT, ARCOUNT đều bằng 0
	resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Copy Question Section
	if len(req) > 12 {
		resp = append(resp, req[12:]...)
	}

	return resp
}

// BuildARecord tạo gói tin phản hồi thành công (NOERROR) chứa địa chỉ IPv4
func BuildARecord(req []byte, ip net.IP) []byte {
	resp := make([]byte, 0, 512)

	// Transaction ID
	resp = append(resp, req[0], req[1])

	// Flags: QR=1, RD=1, RA=0, RCODE=0 (NOERROR)
	resp = append(resp, 0x81, 0x80)

	// QDCOUNT
	resp = append(resp, req[4], req[5])

	// ANCOUNT (1 Answer)
	resp = append(resp, 0x00, 0x01)

	// NSCOUNT (0), ARCOUNT (0)
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)

	// Copy Question Section
	if len(req) > 12 {
		resp = append(resp, req[12:]...)
	}

	// --- Answer Section ---

	// NAME: Sử dụng Message Compression (Pointer) trỏ về offset 12 (0x0C) của byte đầu tiên trong Question
	// Công thức: 11000000 00001100 = 0xC00C
	resp = append(resp, 0xc0, 0x0c)

	// TYPE: A (0x00, 0x01)
	resp = append(resp, 0x00, 0x01)

	// CLASS: IN (0x00, 0x01)
	resp = append(resp, 0x00, 0x01)

	// TTL: 60 giây (4 bytes)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c)

	// RDLENGTH: 4 bytes cho địa chỉ IPv4
	resp = append(resp, 0x00, 0x04)

	// RDATA: Địa chỉ IP
	// net.IP.To4() đảm bảo trích xuất đúng 4 byte IPv4 kể cả khi lưu dưới dạng IPv6-mapped
	ipv4 := ip.To4()
	if ipv4 != nil {
		resp = append(resp, ipv4...)
	} else {
		// Fallback nếu IP không hợp lệ: trả về 0.0.0.0
		resp = append(resp, 0, 0, 0, 0)
	}

	return resp
}

// BuildAAAARecord tạo gói tin phản hồi thành công chứa địa chỉ IPv6
func BuildAAAARecord(req []byte, ip net.IP) []byte {
	resp := make([]byte, 0, 512)

	// 1. Transaction ID
	resp = append(resp, req[0], req[1])

	// 2. Flags: QR=1, RD=1, RA=0, RCODE=0 (NOERROR)
	resp = append(resp, 0x81, 0x80)

	// 3. QDCOUNT
	resp = append(resp, req[4], req[5])

	// 4. ANCOUNT (1 Answer)
	resp = append(resp, 0x00, 0x01)

	// 5. NSCOUNT (0), ARCOUNT (0)
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)

	// 6. Copy Question Section (Safeguard check)
	if len(req) > 12 {
		resp = append(resp, req[12:]...)
	}

	// --- Answer Section ---

	// NAME: Sử dụng Message Compression trỏ về offset 12
	resp = append(resp, 0xc0, 0x0c)

	// TYPE: AAAA (Decimal: 28 -> Hex: 0x00, 0x1c)
	resp = append(resp, 0x00, 0x1c)

	// CLASS: IN (0x00, 0x01)
	resp = append(resp, 0x00, 0x01)

	// TTL: 60 giây (4 bytes)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c)

	// RDLENGTH: 16 bytes cho địa chỉ IPv6 (0x00, 0x10)
	resp = append(resp, 0x00, 0x10)

	// RDATA: Xử lý địa chỉ IPv6 (16 bytes)
	// Hàm To16() của net.IP sẽ chuyển đổi an toàn thành mảng 16 bytes
	ipv6 := ip.To16()
	if ipv6 != nil {
		resp = append(resp, ipv6...)
	} else {
		// Fallback an toàn nếu IP đầu vào không hợp lệ: trả về địa chỉ "::" (16 bytes 0)
		resp = append(resp, make([]byte, 16)...)
	}

	return resp
}

// BuildErrorResponse tạo gói tin phản hồi lỗi tùy chỉnh (ví dụ: SERVFAIL, FORMERR)
func BuildErrorResponse(req []byte, rcode byte) []byte {
	resp := make([]byte, 0, 512)

	// Transaction ID
	resp = append(resp, req[0], req[1])

	// Flags: QR=1, RD=1, và gắn mã RCODE (chỉ lấy 4 bit cuối để an toàn)
	flag2 := byte(0x80) | (rcode & 0x0F)
	resp = append(resp, 0x81, flag2)

	// QDCOUNT
	resp = append(resp, req[4], req[5])

	// ANCOUNT, NSCOUNT, ARCOUNT đều bằng 0
	resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Copy Question Section
	if len(req) > 12 {
		resp = append(resp, req[12:]...)
	}

	return resp
}
