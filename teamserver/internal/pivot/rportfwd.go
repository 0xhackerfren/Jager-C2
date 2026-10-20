package pivot

import (
	"fmt"
	"net"
	"sync"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
)

// RPortFwd is an operator-facing TCP listener that forwards connections
// through the C2 tunnel to a specific target behind the implant.
//
// Example: operator binds 127.0.0.1:3389, traffic forwards through
// the implant to 172.16.1.20:3389 in the internal network.
type RPortFwd struct {
	mu         sync.Mutex
	id         int
	sessionID  string
	tunnels    *TunnelManager
	listener   net.Listener
	bindPort   int
	remoteHost string
	remotePort int
	running    bool
	logger     *zap.Logger
}

func NewRPortFwd(id int, sessionID string, bindPort int, remoteHost string, remotePort int, tm *TunnelManager, logger *zap.Logger) *RPortFwd {
	return &RPortFwd{
		id:         id,
		sessionID:  sessionID,
		tunnels:    tm,
		bindPort:   bindPort,
		remoteHost: remoteHost,
		remotePort: remotePort,
		logger:     logger.Named("rportfwd"),
	}
}

func (rp *RPortFwd) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", rp.bindPort))
	if err != nil {
		return fmt.Errorf("rportfwd bind: %w", err)
	}
	rp.listener = ln
	rp.running = true

	go rp.acceptLoop()

	rp.logger.Info("reverse port forward started",
		zap.Int("local_port", rp.bindPort),
		zap.String("remote", fmt.Sprintf("%s:%d", rp.remoteHost, rp.remotePort)),
		zap.String("session", rp.sessionID))
	return nil
}

func (rp *RPortFwd) Stop() error {
	rp.running = false
	if rp.listener != nil {
		rp.listener.Close()
	}
	return nil
}

func (rp *RPortFwd) ID() int {
	return rp.id
}

func (rp *RPortFwd) BindPort() int {
	return rp.bindPort
}

func (rp *RPortFwd) Remote() string {
	return fmt.Sprintf("%s:%d", rp.remoteHost, rp.remotePort)
}

func (rp *RPortFwd) acceptLoop() {
	for rp.running {
		conn, err := rp.listener.Accept()
		if err != nil {
			if !rp.running {
				return
			}
			continue
		}
		go rp.handleConn(conn)
	}
}

func (rp *RPortFwd) handleConn(conn net.Conn) {
	defer conn.Close()

	chID := rp.tunnels.AllocChannel(rp.sessionID)
	defer rp.tunnels.FreeChannel(chID)

	// Send OPEN with target details
	rp.tunnels.QueueToImplant(rp.sessionID, &pb.TunnelFrame{
		ChannelID:  chID,
		Op:         pb.TunnelOp_OPEN,
		TargetHost: rp.remoteHost,
		TargetPort: uint32(rp.remotePort),
		SessionID:  rp.sessionID,
	})

	done := make(chan struct{}, 2)

	// Operator -> Implant
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				rp.tunnels.QueueToImplant(rp.sessionID, &pb.TunnelFrame{
					ChannelID: chID,
					Op:        pb.TunnelOp_CLOSE,
					SessionID: rp.sessionID,
				})
				return
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			rp.tunnels.QueueToImplant(rp.sessionID, &pb.TunnelFrame{
				ChannelID: chID,
				Op:        pb.TunnelOp_DATA,
				Payload:   payload,
				SessionID: rp.sessionID,
			})
		}
	}()

	// Implant -> Operator
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			frame := rp.tunnels.ReceiveFromImplant(chID)
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
