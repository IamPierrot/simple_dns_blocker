package server

import (
	"fmt"
	"net"

	"github.com/IamPierrot/simple_dns_blocker/internal/blocker"
	"github.com/IamPierrot/simple_dns_blocker/internal/cache"
	"github.com/IamPierrot/simple_dns_blocker/internal/dns"
)

// Server quản lý toàn bộ vòng đời của hệ thống phân giải DNS
type Server struct {
	conn      *net.UDPConn
	blocker   *blocker.Blocker
	forwarder *dns.Forwarder
	dnsCache  *cache.Cache
	addr      string
	port      uint
}

func New(addr string, port uint) *Server {
	blocker := blocker.NewBlocker()
	blocker.Load("/cmd/config/blocklist.txt")

	return &Server{
		conn:      nil,
		blocker:   blocker,
		forwarder: dns.NewForwarder("8.8.8.8:53"), // Mặc định trỏ về Google Public DNS
		dnsCache:  cache.NewCache(),
		addr:      addr,
		port:      port,
	}
}

// Start mở socket và bắt đầu vòng lặp sự kiện lắng nghe UDP
func (s *Server) Start() error {
	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP(s.addr),
		Port: int(s.port),
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("không thể bind vào địa chỉ %s:%d - %w", s.addr, s.port, err)
	}
	s.conn = conn

	fmt.Printf("🚀 DNS Server đang lắng nghe tại %s:%d\n", s.addr, s.port)

	// (Event Loop)
	for {
		buf := make([]byte, 512)
		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Lỗi đọc UDP packet:", err)
			continue
		}

		// Dispatch mỗi request vào một Goroutine riêng biệt
		go func(reqData []byte, cAddr *net.UDPAddr) {
			resp := s.HandleDNSRequest(reqData)
			if resp != nil {
				_, err := s.conn.WriteToUDP(resp, cAddr)
				if err != nil {
					fmt.Printf("Lỗi gửi phản hồi tới %s: %v\n", cAddr.String(), err)
				}
			}
		}(buf[:n], clientAddr)
	}
}

// Close giải phóng tài nguyên mạng
func (s *Server) Close() {
	if s.conn != nil {
		s.conn.Close()
		fmt.Println("🛑 Đã đóng kết nối DNS Server.")
	}
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

	// Tự động phân tích TTL từ phản hồi.
	// Nếu parse lỗi (gói tin dị dạng), thiết lập mặc định là 60 giây.
	ttl, err := dns.ParseTTL(resp)
	if err != nil {
		ttl = 60
	}

	// Lưu vào bộ nhớ đệm
	s.dnsCache.Set(q.Name, q.Type, resp, ttl)

	return resp
}
