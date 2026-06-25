package server

import (
	"errors"
	"fmt"
	"net"

	"github.com/IamPierrot/simple_dns_blocker/internal/blocker"
	"github.com/IamPierrot/simple_dns_blocker/internal/cache"
	"github.com/IamPierrot/simple_dns_blocker/internal/dns"
)

// Server quản lý toàn bộ vòng đời của hệ thống phân giải DNS
type Server struct {
	conns     []*net.UDPConn // Đổi thành slice để lưu nhiều socket
	blocker   *blocker.Blocker
	forwarder *dns.Forwarder
	dnsCache  *cache.Cache
	port      uint
}

func New(port uint) *Server {
	blocker := blocker.NewBlocker()
	blocker.Load("./cmd/config/blocklist")

	return &Server{
		blocker:   blocker,
		forwarder: dns.NewForwarder("8.8.8.8:53"), // Mặc định trỏ về Google Public DNS
		dnsCache:  cache.NewCache(),
		port:      port,
	}
}

// Start mở socket cho cả IPv4 và IPv6
func (s *Server) Start() error {
	// Nếu bạn đang muốn chạy trên localhost để test:
	// Dùng 127.0.0.1 cho IPv4 và ::1 cho IPv6.
	// Nếu muốn public ra ngoài, đổi thành 0.0.0.0 và ::
	addresses := []struct {
		network string
		ip      string
	}{
		{"udp4", "127.0.0.1"},
		{"udp6", "::1"},
	}

	errChan := make(chan error, len(addresses))

	for _, addr := range addresses {
		go func(netType, ip string) {
			udpAddr := &net.UDPAddr{
				IP:   net.ParseIP(ip),
				Port: int(s.port),
			}

			conn, err := net.ListenUDP(netType, udpAddr)
			if err != nil {
				errChan <- fmt.Errorf("lỗi bind %s (%s): %w", netType, ip, err)
				return
			}
			s.conns = append(s.conns, conn)

			fmt.Printf("🚀 DNS Server đang lắng nghe %s tại %s:%d\n", netType, ip, s.port)

			// Chạy Event Loop cho socket này
			s.serve(conn)
		}(addr.network, addr.ip)
	}

	// Đợi tín hiệu lỗi đầu tiên (nếu có)
	return <-errChan
}

// serve chứa logic đọc gói tin với cơ chế chống Goroutine Leak
func (s *Server) serve(conn *net.UDPConn) {
	for {
		buf := make([]byte, 512)
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Kiểm tra xem lỗi có phải do socket đã bị đóng (Graceful Shutdown) hay không
			if errors.Is(err, net.ErrClosed) {
				fmt.Printf("ℹ️ Luồng lắng nghe %s đã được đóng an toàn.\n", conn.LocalAddr().Network())
				return // Thoát hẳn khỏi Goroutine, chấm dứt vòng lặp
			}

			fmt.Println("Lỗi đọc UDP packet:", err)
			// Có thể return luôn ở đây thay vì continue nếu bạn cho rằng
			// các lỗi I/O khác ở mức socket là không thể phục hồi (unrecoverable).
			return
		}

		go func(reqData []byte, cAddr *net.UDPAddr, activeConn *net.UDPConn) {
			resp := s.HandleDNSRequest(reqData)
			if resp != nil {
				_, err := activeConn.WriteToUDP(resp, cAddr)
				if err != nil {
					fmt.Printf("Lỗi gửi phản hồi tới %s: %v\n", cAddr.String(), err)
				}
			}
		}(buf[:n], clientAddr, conn)
	}
}

// Close giải phóng tất cả tài nguyên mạng
func (s *Server) Close() {
	for _, conn := range s.conns {
		if conn != nil {
			conn.Close()
		}
	}
	fmt.Println("🛑 Đã đóng tất cả kết nối DNS Server.")
}

// HandleDNSRequest đóng vai trò là "Router" điều phối luồng dữ liệu.
// Trả về []byte để Goroutine cha thực hiện việc gửi dữ liệu.
func (s *Server) HandleDNSRequest(req []byte) []byte {
	q, err := dns.ParseQuestion(req)
	if err != nil {
		// (Malformed Packets)
		fmt.Println("[CẢNH BÁO] Nhận được gói tin không hợp lệ")
		return dns.BuildErrorResponse(req, 1) // FORMERR
	}

	if s.blocker.IsBlocked(q.Name) {
		fmt.Printf("[BLOCK] Từ chối truy vấn tới: %s (Type: %d)\n", q.Name, q.Type)

		switch q.Type {
		case 1:
			// Type A: Yêu cầu phân giải IPv4 -> Trả về 0.0.0.0
			return dns.BuildARecord(req, net.ParseIP("0.0.0.0"))
		case 28:
			// Type AAAA: Yêu cầu phân giải IPv6 -> Trả về ::
			return dns.BuildAAAARecord(req, net.ParseIP("::"))
		default:
			// Với các loại truy vấn khác (CNAME, TXT, HTTPS, MX...),
			return dns.BuildNXDomain(req)
		}
	}

	if cachedData, ok := s.dnsCache.Get(q.Name, q.Type); ok {
		fmt.Printf("[CACHE HIT] %s\n", q.Name)

		// Ghi đè Transaction ID từ request của client vào dữ liệu lấy từ cache
		cachedData[0] = req[0]
		cachedData[1] = req[1]

		return cachedData
	}

	// 3. Chuyển tiếp truy vấn (Forwarding)
	resp, err := s.forwarder.Query(req)
	if err != nil {
		return dns.BuildErrorResponse(req, 2)
	}

	ttl, err := dns.ParseTTL(resp)
	if err != nil {
		ttl = 60
	}

	// Lưu vào bộ nhớ đệm
	s.dnsCache.Set(q.Name, q.Type, resp, ttl)

	return resp
}
