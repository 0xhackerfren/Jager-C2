package listeners

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"

	"go.uber.org/zap"
)

// ExternalC2Listener implements an External C2 interface.
// Third-party transports (WireGuard, domain fronting CDN, Tor, etc.)
// connect to this listener and relay implant traffic through their
// own transport mechanism.
type ExternalC2Listener struct {
	id       string
	config   *pb.ListenerConfig
	logger   *zap.Logger
	sessions *sessions.Manager
	tasks    TaskQueue

	listener net.Listener
	mu       sync.Mutex
	channels map[string]*extChannel
	done     chan struct{}
}

type extChannel struct {
	id       string
	conn     net.Conn
	implants map[string]bool
}

type extFrame struct {
	Type      string          `json:"type"`
	ChannelID string          `json:"channel_id"`
	ImplantID string          `json:"implant_id"`
	PSK       string          `json:"psk"`
	Data      json.RawMessage `json:"data"`
}

func NewExternalC2Listener(cfg *pb.ListenerConfig, sess *sessions.Manager, tq TaskQueue, logger *zap.Logger) (*ExternalC2Listener, error) {
	return &ExternalC2Listener{
		id:       cfg.Id,
		config:   cfg,
		logger:   logger.Named("ext-c2"),
		sessions: sess,
		tasks:    tq,
		channels: make(map[string]*extChannel),
		done:     make(chan struct{}),
	}, nil
}

func (l *ExternalC2Listener) Start() error {
	addr := fmt.Sprintf("%s:%d", l.config.BindHost, l.config.BindPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("external c2 listen: %w", err)
	}
	l.listener = ln
	l.logger.Info("external C2 listener started", zap.String("addr", addr))

	go l.acceptLoop()
	return nil
}

func (l *ExternalC2Listener) Stop() error {
	close(l.done)
	if l.listener != nil {
		l.listener.Close()
	}

	l.mu.Lock()
	for _, ch := range l.channels {
		ch.conn.Close()
	}
	l.mu.Unlock()

	l.logger.Info("external C2 listener stopped")
	return nil
}

func (l *ExternalC2Listener) ID() string                   { return l.id }
func (l *ExternalC2Listener) Config() *pb.ListenerConfig { return l.config }

func (l *ExternalC2Listener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
				l.logger.Error("accept error", zap.Error(err))
				continue
			}
		}
		go l.handleChannel(conn)
	}
}

func (l *ExternalC2Listener) handleChannel(conn net.Conn) {
	defer conn.Close()

	frame, err := l.readFrame(conn)
	if err != nil {
		l.logger.Warn("channel read error", zap.Error(err))
		return
	}

	if frame.Type != "auth" {
		l.logger.Warn("first frame must be auth", zap.String("got", frame.Type))
		return
	}

	expectedPSK := os.Getenv("JAGER_EXTC2_PSK")
	if expectedPSK == "" {
		l.logger.Error("JAGER_EXTC2_PSK not set — external C2 disabled")
		l.writeFrame(conn, &extFrame{Type: "auth_fail"})
		return
	}
	if frame.PSK != expectedPSK {
		l.logger.Warn("invalid PSK from external channel")
		l.writeFrame(conn, &extFrame{Type: "auth_fail"})
		return
	}

	ch := &extChannel{
		id:       frame.ChannelID,
		conn:     conn,
		implants: make(map[string]bool),
	}

	l.mu.Lock()
	l.channels[ch.id] = ch
	l.mu.Unlock()

	l.writeFrame(conn, &extFrame{Type: "auth_ok", ChannelID: ch.id})
	l.logger.Info("external channel authenticated", zap.String("channel", ch.id))

	for {
		frame, err := l.readFrame(conn)
		if err != nil {
			break
		}

		switch frame.Type {
		case "register":
			l.handleRegister(ch, frame)
		case "checkin":
			l.handleCheckin(ch, frame)
		case "task_result":
			l.handleTaskResult(ch, frame)
		default:
			l.logger.Warn("unknown frame type", zap.String("type", frame.Type))
		}
	}

	l.mu.Lock()
	delete(l.channels, ch.id)
	l.mu.Unlock()
	l.logger.Info("external channel disconnected", zap.String("channel", ch.id))
}

func (l *ExternalC2Listener) handleRegister(ch *extChannel, frame *extFrame) {
	var reg struct {
		pb.ImplantRegistration
		BuildToken string `json:"build_token"`
	}
	if err := json.Unmarshal(frame.Data, &reg); err != nil {
		l.logger.Warn("external C2 register parse failed", zap.Error(err))
		return
	}
	if reg.BuildId == "" || reg.BuildToken == "" {
		return
	}
	if !crypto.ValidateBuildToken(reg.BuildId, reg.BuildToken) {
		return
	}
	reg.ImplantId = frame.ImplantID
	reg.Transport = pb.Transport_TRANSPORT_TCP

	sess := l.sessions.RegisterBeacon(&reg.ImplantRegistration, 60, 20)
	ch.implants[sess.Id] = true

	l.writeFrame(ch.conn, &extFrame{
		Type:      "registered",
		ImplantID: sess.Id,
	})
}

func (l *ExternalC2Listener) handleCheckin(ch *extChannel, frame *extFrame) {
	l.sessions.Checkin(frame.ImplantID)
	tasks := l.tasks.Dequeue(frame.ImplantID, 10)
	if len(tasks) > 0 {
		taskData, _ := json.Marshal(tasks)
		l.writeFrame(ch.conn, &extFrame{
			Type:      "task_push",
			ImplantID: frame.ImplantID,
			Data:      taskData,
		})
	} else {
		l.writeFrame(ch.conn, &extFrame{
			Type:      "no_task",
			ImplantID: frame.ImplantID,
		})
	}
}

func (l *ExternalC2Listener) handleTaskResult(ch *extChannel, frame *extFrame) {
	var result struct {
		TaskID string `json:"task_id"`
		Output []byte `json:"output"`
		Error  string `json:"error"`
	}
	json.Unmarshal(frame.Data, &result)
	l.tasks.Complete(result.TaskID, frame.ImplantID, result.Output, result.Error)
}

func (l *ExternalC2Listener) readFrame(conn net.Conn) (*extFrame, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}

	length := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	if length > 10*1024*1024 {
		return nil, fmt.Errorf("frame too large: %d", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	var frame extFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		return nil, err
	}
	return &frame, nil
}

func (l *ExternalC2Listener) writeFrame(conn net.Conn, frame *extFrame) error {
	data, err := json.Marshal(frame)
	if err != nil {
		return err
	}

	length := len(data)
	header := []byte{
		byte(length >> 24), byte(length >> 16),
		byte(length >> 8), byte(length),
	}

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}
