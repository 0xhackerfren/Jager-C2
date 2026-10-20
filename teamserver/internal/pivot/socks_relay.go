package pivot

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
)

// SocksRelay is an operator-facing SOCKS5 proxy that relays connections
// through an implant's SOCKS5 server via the C2 tunnel channel.
//
// Flow:
//   1. Operator tool connects to SocksRelay (e.g. proxychains -> 127.0.0.1:1080)
//   2. SocksRelay performs SOCKS5 handshake with the operator tool
//   3. SocksRelay opens a tunnel channel to the implant
//   4. SocksRelay relays SOCKS5 CONNECT request through tunnel to implant SOCKS5
//   5. Bidirectional data relay: operator <-> tunnel <-> implant <-> target
type SocksRelay struct {
	mu        sync.Mutex
	sessionID string
	tunnels   *TunnelManager
	listener  net.Listener
	port      int
	running   bool
	logger    *zap.Logger
}

func NewSocksRelay(sessionID string, port int, tm *TunnelManager, logger *zap.Logger) *SocksRelay {
	return &SocksRelay{
		sessionID: sessionID,
		tunnels:   tm,
		port:      port,
		logger:    logger.Named("socks-relay"),
	}
}

func (sr *SocksRelay) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", sr.port))
	if err != nil {
		return fmt.Errorf("socks relay bind: %w", err)
	}
	sr.listener = ln
	sr.running = true

	go sr.acceptLoop()

	sr.logger.Info("SOCKS relay started",
		zap.Int("port", sr.port),
		zap.String("session", sr.sessionID))
	return nil
}

func (sr *SocksRelay) Stop() error {
	sr.running = false
	if sr.listener != nil {
		sr.listener.Close()
	}
	return nil
}

func (sr *SocksRelay) Port() int {
	return sr.port
}

func (sr *SocksRelay) acceptLoop() {
	for sr.running {
		conn, err := sr.listener.Accept()
		if err != nil {
			if !sr.running {
				return
			}
			continue
		}
		go sr.handleConn(conn)
	}
}

func (sr *SocksRelay) handleConn(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 auth negotiation with operator tool
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// Read CONNECT request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse target from SOCKS5 request
	var targetHost string
	var targetPort uint16
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		targetHost = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		targetPort = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // Domain
		dlen := int(buf[4])
		if n < 5+dlen+2 {
			return
		}
		targetHost = string(buf[5 : 5+dlen])
		targetPort = binary.BigEndian.Uint16(buf[5+dlen : 7+dlen])
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		targetHost = net.IP(buf[4:20]).String()
		targetPort = binary.BigEndian.Uint16(buf[20:22])
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Allocate a tunnel channel
	chID := sr.tunnels.AllocChannel(sr.sessionID)
	defer sr.tunnels.FreeChannel(chID)

	// Send OPEN frame to implant and wait for connect ack before SOCKS5 success
	sr.tunnels.QueueToImplant(sr.sessionID, &pb.TunnelFrame{
		ChannelID:  chID,
		Op:         pb.TunnelOp_OPEN,
		TargetHost: targetHost,
		TargetPort: uint32(targetPort),
		SessionID:  sr.sessionID,
	})

	ack := sr.tunnels.WaitForFirstFrame(chID, 15*time.Second)
	if ack == nil || ack.Op == pb.TunnelOp_CLOSE {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional relay
	done := make(chan struct{}, 2)

	// Operator -> Implant (read from operator socket, send as DATA frames)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				sr.tunnels.QueueToImplant(sr.sessionID, &pb.TunnelFrame{
					ChannelID: chID,
					Op:        pb.TunnelOp_CLOSE,
					SessionID: sr.sessionID,
				})
				return
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			sr.tunnels.QueueToImplant(sr.sessionID, &pb.TunnelFrame{
				ChannelID: chID,
				Op:        pb.TunnelOp_DATA,
				Payload:   payload,
				SessionID: sr.sessionID,
			})
		}
	}()

	// Implant -> Operator (receive frames from implant, write to operator socket)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			frame := sr.tunnels.ReceiveFromImplant(chID)
			if frame == nil {
				return
			}
			switch frame.Op {
			case pb.TunnelOp_DATA:
				if _, err := conn.Write(frame.Payload); err != nil {
					return
				}
			case pb.TunnelOp_CLOSE:
				return
			}
		}
	}()

	<-done
}

// Suppress unused import warning
var _ = io.Copy
