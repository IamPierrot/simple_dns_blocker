package dns

import (
	"encoding/binary"
	"fmt"
)

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ExtractDomain trích xuất tên miền từ gói tin thô
func ExtractDomain(packet []byte) (string, error) {
	if len(packet) < 12 {
		return "", fmt.Errorf("invalid dns packet")
	}

	buf := NewBytePacketBuffer(packet)

	// Bỏ qua phần Header (12 bytes)
	_, _ = buf.ReadChunk(12)

	return buf.ReadQName()
}

// ParseQuestion phân tích toàn bộ Question Section từ gói tin
func ParseQuestion(packet []byte) (*Question, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("invalid dns packet length")
	}

	buf := NewBytePacketBuffer(packet)

	// Bỏ qua 12 bytes Header đầu tiên
	if _, err := buf.ReadChunk(12); err != nil {
		return nil, fmt.Errorf("failed to skip header: %w", err)
	}

	// Đọc QNAME (Tên miền)
	name, err := buf.ReadQName()
	if err != nil {
		return nil, fmt.Errorf("failed to read qname: %w", err)
	}

	// Đọc QTYPE (2 bytes)
	typeChunk, err := buf.ReadChunk(2)
	if err != nil {
		return nil, fmt.Errorf("failed to read qtype: %w", err)
	}
	// Chuyển đổi byte slice thành uint16 theo thứ tự mạng chuẩn
	qType := binary.BigEndian.Uint16(typeChunk)

	// Đọc QCLASS (2 bytes)
	classChunk, err := buf.ReadChunk(2)
	if err != nil {
		return nil, fmt.Errorf("failed to read qclass: %w", err)
	}
	qClass := binary.BigEndian.Uint16(classChunk)

	return &Question{
		Name:  name,
		Type:  qType,
		Class: qClass,
	}, nil
}

// ParseTTL trích xuất giá trị TTL (tính bằng giây) từ bản ghi Answer đầu tiên
func ParseTTL(packet []byte) (uint32, error) {
	// Kích thước tối thiểu của một header DNS là 12 bytes
	if len(packet) < 12 {
		return 0, fmt.Errorf("invalid packet length: too short")
	}

	// Trích xuất số lượng Question và Answer từ Header
	// QDCOUNT nằm ở byte 4-5, ANCOUNT nằm ở byte 6-7
	qdCount := binary.BigEndian.Uint16(packet[4:6])
	anCount := binary.BigEndian.Uint16(packet[6:8])

	// Nếu không có câu trả lời nào, không có TTL để bóc tách
	if anCount == 0 {
		return 0, fmt.Errorf("no answer records found in packet")
	}

	buf := NewBytePacketBuffer(packet)

	// Bỏ qua 12 bytes Header
	if _, err := buf.ReadChunk(12); err != nil {
		return 0, err
	}

	// 1. Duyệt và bỏ qua toàn bộ Question Section
	for i := 0; i < int(qdCount); i++ {
		if err := skipName(buf); err != nil {
			return 0, fmt.Errorf("failed to skip QNAME: %w", err)
		}
		// Bỏ qua QTYPE (2 bytes) và QCLASS (2 bytes) = 4 bytes
		if _, err := buf.ReadChunk(4); err != nil {
			return 0, err
		}
	}

	// 2. Đang ở vị trí bắt đầu của Answer Section đầu tiên

	// Bỏ qua trường NAME của Answer (có thể là chuỗi label hoặc pointer)
	if err := skipName(buf); err != nil {
		return 0, fmt.Errorf("failed to skip Answer Name: %w", err)
	}

	// Bỏ qua TYPE (2 bytes) và CLASS (2 bytes) = 4 bytes
	if _, err := buf.ReadChunk(4); err != nil {
		return 0, err
	}

	// 3. Đọc trường TTL (4 bytes)
	ttlChunk, err := buf.ReadChunk(4)
	if err != nil {
		return 0, fmt.Errorf("failed to read TTL: %w", err)
	}

	// Chuyển đổi 4 bytes thành số nguyên không dấu 32-bit theo chuẩn Big Endian
	ttl := binary.BigEndian.Uint32(ttlChunk)

	return ttl, nil
}

func skipName(buf *BytePacketBuffer) error {
	for {
		val, err := buf.Read()
		if err != nil {
			return err
		}

		if val == 0 {
			break // Ký tự null (0x00) đánh dấu kết thúc label bình thường
		}

		// Kiểm tra 2 bit đầu tiên (Mask với 11000000). Nếu là 11, đây là một pointer.
		if (val & 0xC0) == 0xC0 {
			// Pointer chiếm 2 bytes, nên ta chỉ cần đọc thêm 1 byte nữa và thoát
			// Pointer luôn là điểm kết thúc của một Name.
			_, err := buf.Read()
			return err
		}

		// Nếu không phải pointer, `val` chính là độ dài của label tiếp theo (ví dụ: 3 cho "com")
		_, err = buf.ReadChunk(int(val))
		if err != nil {
			return err
		}
	}
	return nil
}
