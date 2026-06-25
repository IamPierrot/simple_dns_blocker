package dns

import (
	"fmt"
	"net"
	"time"
)

// Forwarder cấu hình máy chủ DNS cấp trên (ví dụ: "8.8.8.8:53")
type Forwarder struct {
	Upstream string
}

// NewForwarder khởi tạo một Forwarder mới
func NewForwarder(upstream string) *Forwarder {
	return &Forwarder{
		Upstream: upstream,
	}
}

// Query chuyển tiếp gói tin DNS nguyên bản tới upstream và trả về kết quả
func (f *Forwarder) Query(req []byte) ([]byte, error) {
	conn, err := net.Dial("udp", f.Upstream)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream: %w", err)
	}
	defer conn.Close()

	// Thiết lập Timeout (ví dụ: 2 giây) để tránh treo goroutine khi rớt mạng
	err = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Gửi gói tin request gốc lên upstream
	_, err = conn.Write(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to upstream: %w", err)
	}

	// Chuẩn bị buffer để nhận phản hồi
	// Dùng 4096 bytes thay vì 512 để đề phòng các gói tin có hỗ trợ EDNS0 (thường trả về payload lớn)
	respBuf := make([]byte, 4096)

	// Đọc kết quả trả về từ upstream
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from upstream: %w", err)
	}

	return respBuf[:n], nil
}
