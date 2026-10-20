package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/auth"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/builds"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/events"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/scripting"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ManagementAPI provides HTTP REST endpoints for operator control.
// This runs alongside gRPC and is what the MCP server talks to.
type ManagementAPI struct {
	srv    *Server
	logger *zap.Logger
}

func NewManagementAPI(srv *Server, logger *zap.Logger) *ManagementAPI {
	return &ManagementAPI{srv: srv, logger: logger}
}

func (m *ManagementAPI) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/mgmt/ping", m.handlePing)
	mux.HandleFunc("/mgmt/events", m.handleEvents)
	mux.HandleFunc("/mgmt/events/poll", m.handleEventsPoll)
	mux.HandleFunc("/mgmt/audit", m.handleAuditTrail)
	mux.HandleFunc("/mgmt/hooks", m.handleListHooks)
	mux.HandleFunc("/mgmt/hook/register", m.handleRegisterHook)
	mux.HandleFunc("/mgmt/sessions", m.handleSessions)
	mux.HandleFunc("/mgmt/beacons", m.handleBeacons)
	mux.HandleFunc("/mgmt/task", m.handleTask)
	mux.HandleFunc("/mgmt/tasks", m.handleListTasks)
	mux.HandleFunc("/mgmt/task/wait", m.handleWaitTask)
	mux.HandleFunc("/mgmt/task/purge", m.handleTaskPurge)
	mux.HandleFunc("/mgmt/listener/start", m.handleStartListener)
	mux.HandleFunc("/mgmt/listener/stop", m.handleStopListener)
	mux.HandleFunc("/mgmt/listeners", m.handleListListeners)
	mux.HandleFunc("/mgmt/session/kill", m.handleKillSession)
	mux.HandleFunc("/mgmt/session/sleep", m.handleSetSleep)
	mux.HandleFunc("/mgmt/session/note", m.handleSessionNote)
	mux.HandleFunc("/mgmt/session/label", m.handleSessionLabel)
	mux.HandleFunc("/mgmt/credential", m.handleAddCredential)
	mux.HandleFunc("/mgmt/credentials", m.handleListCredentials)
	mux.HandleFunc("/mgmt/target", m.handleAddTarget)
	mux.HandleFunc("/mgmt/targets", m.handleListTargets)
	mux.HandleFunc("/mgmt/finding", m.handleAddFinding)
	mux.HandleFunc("/mgmt/findings", m.handleListFindings)
	mux.HandleFunc("/mgmt/summary", m.handleSummary)

	// Pivot management endpoints
	mux.HandleFunc("/mgmt/pivots", m.handleListPivots)
	mux.HandleFunc("/mgmt/pivots/socks/start", m.handleSocksStart)
	mux.HandleFunc("/mgmt/pivots/socks/stop", m.handleSocksStop)
	mux.HandleFunc("/mgmt/pivots/portfwd", m.handlePortFwd)
	mux.HandleFunc("/mgmt/pivots/stop", m.handlePivotStop)

	// P2P linked beacon management
	mux.HandleFunc("/mgmt/p2p/links", m.handleP2PList)
	mux.HandleFunc("/mgmt/p2p/link", m.handleP2PLink)
	mux.HandleFunc("/mgmt/p2p/route", m.handleP2PRoute)
	mux.HandleFunc("/mgmt/campaign/export", m.handleCampaignExport)

	// Loot management
	mux.HandleFunc("/mgmt/loot", m.handleListLoot)
	mux.HandleFunc("/mgmt/loot/get", m.handleGetLoot)
	mux.HandleFunc("/mgmt/loot/store", m.handleStoreLoot)
	mux.HandleFunc("/mgmt/loot/stats", m.handleLootStats)
	mux.HandleFunc("/mgmt/screenshots", m.handleListScreenshots)
	mux.HandleFunc("/mgmt/screenshot", m.handleGetScreenshot)

	// Build artifact management (polymorphic implants / stage payloads)
	mux.HandleFunc("/mgmt/builds", m.handleListBuilds)
	mux.HandleFunc("/mgmt/build/implant", m.handleBuildImplant)
	mux.HandleFunc("/mgmt/build/pipeline", m.handleBuildPipeline)
	mux.HandleFunc("/mgmt/build/stager", m.handleBuildStager)
	mux.HandleFunc("/mgmt/build/download", m.handleBuildDownload)
	mux.HandleFunc("/mgmt/build/stage", m.handleUploadStage)
	mux.HandleFunc("/mgmt/build/register", m.handleRegisterBuild)

	// Redirector management (C2 infrastructure)
	mux.HandleFunc("/api/v1/redirectors", m.handleRedirectors)
	mux.HandleFunc("/api/v1/redirectors/", m.handleRedirectorByID)

	return mux
}

func jsonResp(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (m *ManagementAPI) handlePing(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, map[string]interface{}{"success": true, "message": "pong"})
}

func (m *ManagementAPI) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := m.srv.events.Subscribe()
	defer m.srv.events.Unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()
		}
	}
}

func (m *ManagementAPI) handleEventsPoll(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	sinceStr := r.URL.Query().Get("since")
	since := 60
	if sinceStr != "" {
		if n, err := strconv.Atoi(sinceStr); err == nil {
			since = n
		}
	}
	typesStr := r.URL.Query().Get("types")
	var typeFilter []events.EventType
	if typesStr != "" {
		for _, t := range splitCSV(typesStr) {
			typeFilter = append(typeFilter, events.EventType(t))
		}
	}

	recent := m.srv.events.Recent(time.Duration(since)*time.Second, typeFilter)
	jsonResp(w, map[string]interface{}{
		"success": true,
		"events":  recent,
		"count":   len(recent),
	})
}

func splitCSV(s string) []string {
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			if len(part) > 0 {
				result = append(result, part)
			}
			start = i + 1
		}
	}
	return result
}

func (m *ManagementAPI) handleAuditTrail(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermCampaignManage) {
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	audit := m.srv.campaign.GetAuditTrail(limit)
	jsonResp(w, map[string]interface{}{"audit": audit, "count": len(audit)})
}

func (m *ManagementAPI) handleListHooks(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermCampaignManage) {
		return
	}
	hooks := m.srv.script.ListHooks()
	jsonResp(w, map[string]interface{}{"hooks": hooks, "count": len(hooks)})
}

func (m *ManagementAPI) handleRegisterHook(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermCampaignManage) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	var hook scripting.Hook
	if err := json.NewDecoder(r.Body).Decode(&hook); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if hook.Name == "" {
		jsonErr(w, 400, "name required")
		return
	}
	m.srv.script.RegisterHook(hook)
	m.auditLog(r, "hook.register", "", "", hook.Name)
	jsonResp(w, map[string]interface{}{"success": true, "name": hook.Name})
}

func (m *ManagementAPI) handleSessions(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	sessions := m.srv.sessions.GetSessions(true)
	jsonResp(w, map[string]interface{}{"sessions": sessions})
}

func (m *ManagementAPI) handleBeacons(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	beacons := m.srv.sessions.GetBeacons(true)
	jsonResp(w, map[string]interface{}{"beacons": beacons})
}

func (m *ManagementAPI) handleTask(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermTaskCreate) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}

	var req TaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	taskType, err := parseTaskType(req.Type)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if taskType == pb.TaskType_TASK_UNKNOWN && len(req.Type) > 0 {
		jsonErr(w, 400, "unknown task type")
		return
	}

	requestData, err := buildTaskRequestData(taskType, req.Args, req.RawData, req.Timeout)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	task := &pb.Task{
		Id:          uuid.New().String(),
		SessionId:   req.SessionID,
		Type:        taskType,
		State:       pb.TaskState_TASK_STATE_QUEUED,
		RequestData: requestData,
		CreatedAt:   timestamppb.Now(),
		CreatedBy:   m.operatorID(r),
	}

	if err := m.srv.tasks.Enqueue(task); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	m.logger.Info("task queued via mgmt API",
		zap.String("task_id", task.Id),
		zap.String("session_id", req.SessionID),
	)
	m.auditLog(r, "task.create", req.SessionID, task.Id, taskType.String())
	writeC2State(m.srv.cfg.Workspace, "task_queued", map[string]interface{}{
		"task_id": task.Id, "session_id": req.SessionID, "type": taskType.String(),
	})
	jsonResp(w, map[string]interface{}{"task_id": task.Id, "success": true})
}

func (m *ManagementAPI) handleListTasks(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermTaskView) {
		return
	}
	sessionID := r.URL.Query().Get("session_id")
	tasks := m.srv.tasks.List(sessionID, pb.TaskState_TASK_STATE_QUEUED, 100)
	jsonResp(w, map[string]interface{}{"tasks": tasks})
}

func (m *ManagementAPI) handleTaskPurge(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermTaskCreate) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if req.SessionID == "" {
		jsonErr(w, 400, "session_id required")
		return
	}
	before := m.srv.tasks.List(req.SessionID, pb.TaskState_TASK_STATE_QUEUED, 1000)
	m.srv.tasks.PurgeSessionTasks(req.SessionID)
	jsonResp(w, map[string]interface{}{
		"purged":     len(before),
		"session_id": req.SessionID,
	})
}

func (m *ManagementAPI) handleWaitTask(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermTaskView) {
		return
	}
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		jsonErr(w, 400, "task_id required")
		return
	}

	// Respect client timeout_ms (default 120s, max 300s)
	deadline := 120
	if tms := r.URL.Query().Get("timeout_ms"); tms != "" {
		if v, err := strconv.Atoi(tms); err == nil && v > 0 {
			d := v / 1000
			if d < 5 {
				d = 5
			} else if d > 300 {
				d = 300
			}
			deadline = d
		}
	}
	for i := 0; i < deadline*2; i++ {
		task, err := m.srv.tasks.Get(taskID)
		if err != nil {
			jsonErr(w, 404, err.Error())
			return
		}
		if task.State == pb.TaskState_TASK_STATE_COMPLETED || task.State == pb.TaskState_TASK_STATE_FAILED {
			jsonResp(w, taskResponseJSON(task))
			return
		}
		select {
		case <-r.Context().Done():
			jsonErr(w, 408, "client disconnected")
			return
		default:
		}
		// Use a short sleep for polling
		sleepMs := 500
		_ = sleepMs
		// Simple busy-wait with channel
		ch := make(chan struct{})
		go func() {
			defer close(ch)
			// 500ms sleep
			select {
			case <-r.Context().Done():
			case <-func() <-chan struct{} {
				c := make(chan struct{})
				go func() { defer close(c); <-timeAfter(500) }()
				return c
			}():
			}
		}()
		<-ch
	}
	jsonErr(w, 408, "timeout waiting for task completion")
}

func timeAfter(ms int) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}()
	return ch
}

func (m *ManagementAPI) handleStartListener(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermListenerCreate) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}

	var req struct {
		Transport string `json:"transport"`
		Host      string `json:"host"`
		Port      int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	transport := pb.Transport_TRANSPORT_HTTPS
	switch req.Transport {
	case "dns":
		transport = pb.Transport_TRANSPORT_DNS
	case "tcp":
		transport = pb.Transport_TRANSPORT_TCP
	case "smb":
		transport = pb.Transport_TRANSPORT_SMB
	}

	cfg := &pb.ListenerConfig{
		Id:        uuid.New().String(),
		Transport: transport,
		BindHost:  req.Host,
		BindPort:  uint32(req.Port),
		StartedAt: timestamppb.Now(),
	}

	if err := m.srv.listen.Start(cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	m.auditLog(r, "listener.start", "", "", fmt.Sprintf("%s:%d", req.Host, req.Port))
	jsonResp(w, map[string]interface{}{"listener_id": cfg.Id, "success": true})
}

func (m *ManagementAPI) handleStopListener(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermListenerStop) {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		jsonErr(w, 400, "id required")
		return
	}
	if err := m.srv.listen.Stop(id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	m.auditLog(r, "listener.stop", "", "", id)
	jsonResp(w, map[string]interface{}{"success": true})
}

func (m *ManagementAPI) handleListListeners(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	all := m.srv.listen.List()
	jsonResp(w, map[string]interface{}{"listeners": all})
}

func (m *ManagementAPI) handleKillSession(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionKill) {
		return
	}
	var req struct {
		ID    string `json:"id"`
		Force bool   `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := m.srv.sessions.Kill(req.ID, req.Force); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	m.auditLog(r, "session.kill", req.ID, "", "")
	jsonResp(w, map[string]interface{}{"success": true})
}

func (m *ManagementAPI) handleSetSleep(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	var req struct {
		ID       string `json:"id"`
		Interval int    `json:"interval"`
		Jitter   int    `json:"jitter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := m.srv.tasks.QueueSleepChange(req.ID, uint32(req.Interval), uint32(req.Jitter)); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	m.auditLog(r, "session.sleep", req.ID, "", fmt.Sprintf("interval=%d jitter=%d", req.Interval, req.Jitter))
	jsonResp(w, map[string]interface{}{"success": true})
}

func (m *ManagementAPI) handleAddCredential(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermCredAdd) {
		return
	}
	var cred pb.Credential
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if cred.Id == "" {
		cred.Id = uuid.New().String()
	}
	if err := m.srv.loot.AddCredential(&cred); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	m.auditLog(r, "cred.add", cred.SessionId, "", cred.Username)
	if m.srv.events != nil {
		m.srv.events.Publish(events.Event{
			Type:      events.EventCredFound,
			SessionID: cred.SessionId,
			Data: map[string]interface{}{
				"id":       cred.Id,
				"domain":   cred.Domain,
				"username": cred.Username,
			},
		})
	}
	jsonResp(w, map[string]interface{}{"success": true, "id": cred.Id})
}

func (m *ManagementAPI) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermCredView) {
		return
	}
	domain := r.URL.Query().Get("domain")
	creds, err := m.srv.loot.ListCredentials(domain, pb.CredType_CRED_UNKNOWN)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, map[string]interface{}{"credentials": creds})
}

func (m *ManagementAPI) handleAddTarget(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermTaskCreate) {
		return
	}
	var target pb.Target
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if target.Id == "" {
		target.Id = uuid.New().String()
	}
	if err := m.srv.loot.AddTarget(&target); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, map[string]interface{}{"success": true, "id": target.Id})
}

func (m *ManagementAPI) handleListTargets(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	targets, err := m.srv.loot.ListTargets(false)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, map[string]interface{}{"targets": targets})
}

func (m *ManagementAPI) handleAddFinding(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermTaskCreate) {
		return
	}
	var finding pb.Finding
	if err := json.NewDecoder(r.Body).Decode(&finding); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if finding.Id == "" {
		finding.Id = uuid.New().String()
	}
	if err := m.srv.loot.AddFinding(&finding); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, map[string]interface{}{"success": true, "id": finding.Id})
}

func (m *ManagementAPI) handleListFindings(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	severity := r.URL.Query().Get("severity")
	findings, err := m.srv.loot.ListFindings(severity)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, map[string]interface{}{"findings": findings})
}

func (m *ManagementAPI) handleSummary(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	summary, err := m.srv.loot.GetSummary(m.srv.sessions, m.srv.listen)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, summary)
}

// ---- Pivot Management Handlers ----

func (m *ManagementAPI) handleListPivots(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	pivots := m.srv.pivots.ListPivots()
	jsonResp(w, map[string]interface{}{"pivots": pivots})
}

func (m *ManagementAPI) handleSocksStart(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
		Port      int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if req.Port == 0 {
		req.Port = 1080
	}

	// Queue TASK_SOCKS_START on the implant
	task := &pb.Task{
		Id:          uuid.New().String(),
		SessionId:   req.SessionID,
		Type:        pb.TaskType(53), // TASK_SOCKS_START
		State:       pb.TaskState_TASK_STATE_QUEUED,
		RequestData: []byte(fmt.Sprintf(`{"port":%d}`, req.Port)),
		CreatedAt:   timestamppb.Now(),
	}
	if err := m.srv.tasks.Enqueue(task); err != nil {
		jsonErr(w, 400, fmt.Sprintf("failed to queue SOCKS task: %s", err.Error()))
		return
	}

	// Start operator-facing SOCKS relay
	info, err := m.srv.pivots.StartSocksRelay(req.SessionID, req.Port)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	m.logger.Info("SOCKS pivot started",
		zap.Int("pivot_id", info.ID),
		zap.Int("port", info.BindPort),
		zap.String("session", req.SessionID))

	jsonResp(w, map[string]interface{}{
		"success":  true,
		"pivot_id": info.ID,
		"port":     info.BindPort,
		"message":  fmt.Sprintf("SOCKS5 relay available at 127.0.0.1:%d", info.BindPort),
	})
}

func (m *ManagementAPI) handleSocksStop(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
		PivotID   int    `json:"pivot_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	// Queue TASK_SOCKS_STOP on the implant
	task := &pb.Task{
		Id:          uuid.New().String(),
		SessionId:   req.SessionID,
		Type:        pb.TaskType(54), // TASK_SOCKS_STOP
		State:       pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt:   timestamppb.Now(),
	}
	_ = m.srv.tasks.Enqueue(task)

	// Stop the operator relay
	if err := m.srv.pivots.StopSocksRelay(req.PivotID); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}

	jsonResp(w, map[string]interface{}{"success": true})
}

func (m *ManagementAPI) handlePortFwd(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	if r.Method == http.MethodDelete {
		m.handlePortFwdRemove(w, r)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST or DELETE required")
		return
	}

	var req struct {
		SessionID  string `json:"session_id"`
		BindPort   int    `json:"bind_port"`
		RemoteHost string `json:"remote_host"`
		RemotePort int    `json:"remote_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	type portFwdArgs struct {
		LocalPort  int    `json:"local_port"`
		RemoteHost string `json:"remote_host"`
		RemotePort int    `json:"remote_port"`
	}
	argsJSON, err := json.Marshal(portFwdArgs{
		LocalPort:  req.BindPort,
		RemoteHost: req.RemoteHost,
		RemotePort: req.RemotePort,
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	// Queue TASK_PORTFWD_ADD on the implant
	task := &pb.Task{
		Id:          uuid.New().String(),
		SessionId:   req.SessionID,
		Type:        pb.TaskType(55), // TASK_PORTFWD_ADD
		State:       pb.TaskState_TASK_STATE_QUEUED,
		RequestData: argsJSON,
		CreatedAt:   timestamppb.Now(),
	}
	if err := m.srv.tasks.Enqueue(task); err != nil {
		jsonErr(w, 400, fmt.Sprintf("failed to queue portfwd task: %s", err.Error()))
		return
	}

	// Start operator-facing port forward relay
	info, err := m.srv.pivots.StartPortForward(req.SessionID, req.BindPort, req.RemoteHost, req.RemotePort)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	m.logger.Info("port forward started",
		zap.Int("pivot_id", info.ID),
		zap.Int("bind_port", req.BindPort),
		zap.String("remote", info.Remote))

	jsonResp(w, map[string]interface{}{
		"success":  true,
		"pivot_id": info.ID,
		"port":     info.BindPort,
		"remote":   info.Remote,
		"message":  fmt.Sprintf("Port forward 127.0.0.1:%d -> %s", info.BindPort, info.Remote),
	})
}

func (m *ManagementAPI) handlePortFwdRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		PivotID   int    `json:"pivot_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	// Queue TASK_PORTFWD_RM on the implant
	task := &pb.Task{
		Id:          uuid.New().String(),
		SessionId:   req.SessionID,
		Type:        pb.TaskType(56), // TASK_PORTFWD_RM
		State:       pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt:   timestamppb.Now(),
	}
	_ = m.srv.tasks.Enqueue(task)

	if err := m.srv.pivots.StopPortForward(req.PivotID); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	jsonResp(w, map[string]interface{}{"success": true})
}

func (m *ManagementAPI) handlePivotStop(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		jsonErr(w, 405, "POST or DELETE required")
		return
	}

	var req struct {
		PivotID int `json:"pivot_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}

	if err := m.srv.pivots.StopPivot(req.PivotID); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	jsonResp(w, map[string]interface{}{"success": true})
}

func (m *ManagementAPI) handleBuildImplant(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermBuildImplant) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	req, err := decodeBuildRequest(r)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	result, err := m.srv.engine.GenerateImplant(req)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	m.auditLog(r, "build.implant", "", "", result.BuildID)
	jsonResp(w, buildResponseMap(result))
}

// handleBuildPipeline runs full implant + encrypted stage + C stager (MinGW) pipeline.
func (m *ManagementAPI) handleBuildPipeline(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermBuildImplant) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	req, err := decodeBuildRequest(r)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	result, err := m.srv.engine.GeneratePipeline(req)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	m.auditLog(r, "build.pipeline", "", "", result.BuildID)
	jsonResp(w, buildResponseMap(result))
}

// handleBuildStager triggers C stager compilation via the Python builder (MinGW toolchain).
func (m *ManagementAPI) handleBuildStager(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermBuildStager) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	req, err := decodeBuildRequest(r)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	result, err := m.srv.engine.GenerateStager(req)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	m.auditLog(r, "build.stager", "", "", result.BuildID)
	jsonResp(w, buildResponseMap(result))
}

func (m *ManagementAPI) handleBuildDownload(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermBuildImplant) {
		return
	}
	if r.Method != http.MethodGet {
		jsonErr(w, 405, "GET required")
		return
	}
	buildID := r.URL.Query().Get("id")
	artifact := r.URL.Query().Get("artifact") // implant | stager | stage
	if buildID == "" {
		jsonErr(w, 400, "id required")
		return
	}
	if artifact == "stage" {
		if !m.requirePerm(w, r, auth.PermBuildStage) {
			return
		}
		payload, err := m.srv.builds.GetStagePayload(buildID)
		if err != nil {
			jsonErr(w, 404, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(payload)
		return
	}
	data, err := m.srv.builds.GetBuildData(buildID)
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func decodeBuildRequest(r *http.Request) (builds.BuildRequest, error) {
	var req builds.BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, err
	}
	return req, nil
}

func buildResponseMap(result *builds.BuildResult) map[string]interface{} {
	out := map[string]interface{}{
		"success":   result.Success,
		"build_id":  result.BuildID,
		"stage_url": result.StageURL,
		"source":    "teamserver",
	}
	if result.Implant != nil {
		out["implant"] = result.Implant
	}
	if result.Stager != nil {
		out["stager"] = result.Stager
	}
	if result.ProfileID != "" {
		out["profile_id"] = result.ProfileID
	}
	if result.Error != "" {
		out["error"] = result.Error
	}
	return out
}

func (m *ManagementAPI) handleListBuilds(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermBuildImplant) {
		return
	}
	if r.Method != http.MethodGet {
		jsonErr(w, 405, "GET required")
		return
	}
	builds := m.srv.builds.List()
	out := make([]map[string]interface{}, 0, len(builds))
	for _, b := range builds {
		out = append(out, map[string]interface{}{
			"id":             b.ID,
			"type":           b.Type,
			"format":         b.Format,
			"profile":        b.Profile,
			"save_path":      b.SavePath,
			"created_at":     b.CreatedAt,
			"size":           b.Size,
			"seed":           b.Seed,
			"profile_hash":   b.ProfileHash,
			"integrity_hash": b.IntegrityHash,
			"platform":       b.Platform,
		})
	}
	jsonResp(w, map[string]interface{}{"builds": out, "count": len(out)})
}

func (m *ManagementAPI) handleRegisterBuild(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermBuildImplant) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		BuildID  string `json:"build_id"`
		Type     string `json:"type"`
		Format   string `json:"format"`
		Profile  string `json:"profile"`
		SavePath string `json:"save_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if req.BuildID == "" {
		jsonErr(w, 400, "build_id required")
		return
	}
	if err := m.srv.builds.Register(req.BuildID, req.Type, req.Format, req.Profile, req.SavePath); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, map[string]interface{}{"success": true, "build_id": req.BuildID})
}

func (m *ManagementAPI) handleUploadStage(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermBuildImplant) {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		BuildID    string `json:"build_id"`
		PayloadB64 string `json:"payload_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if req.BuildID == "" || req.PayloadB64 == "" {
		jsonErr(w, 400, "build_id and payload_b64 required")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	m.srv.builds.StoreStagePayload(req.BuildID, payload)
	jsonResp(w, map[string]interface{}{
		"success":   true,
		"build_id":  req.BuildID,
		"size":      len(payload),
		"stage_url": fmt.Sprintf("/api/v1/stage?id=%s", req.BuildID),
	})
}

func (m *ManagementAPI) handleP2PList(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	if r.Method != http.MethodGet {
		jsonErr(w, 405, "GET required")
		return
	}
	if m.srv.p2p == nil {
		jsonResp(w, map[string]interface{}{"links": []interface{}{}})
		return
	}
	jsonResp(w, map[string]interface{}{"links": m.srv.p2p.ListLinks()})
}

func (m *ManagementAPI) handleP2PLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	var req struct {
		Parent    string `json:"parent_session"`
		Child     string `json:"child_session"`
		Transport string `json:"transport"`
		PipeName  string `json:"pipe_name"`
		Port      int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if req.Parent == "" || req.Child == "" {
		jsonErr(w, 400, "parent_session and child_session required")
		return
	}
	if req.Transport == "" {
		req.Transport = "pipe"
	}
	m.srv.p2p.AddLink(req.Parent, req.Child, req.Transport, req.PipeName, req.Port)
	writeC2State(m.srv.cfg.Workspace, "p2p_link", map[string]interface{}{
		"parent": req.Parent, "child": req.Child, "transport": req.Transport,
	})
	jsonResp(w, map[string]interface{}{"success": true})
}

func (m *ManagementAPI) handleP2PRoute(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		jsonErr(w, 400, "session_id required")
		return
	}
	route := m.srv.p2p.GetRoute(sessionID)
	jsonResp(w, map[string]interface{}{"session_id": sessionID, "route": route})
}

func (m *ManagementAPI) handleCampaignExport(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermCampaignManage) {
		return
	}
	if r.Method != http.MethodGet {
		jsonErr(w, 405, "GET required")
		return
	}
	sessions := m.srv.sessions.GetSessions(true)
	tasks := m.srv.tasks.List("", pb.TaskState_TASK_STATE_COMPLETED, 500)
	export := map[string]interface{}{
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"sessions":    sessions,
		"tasks":       tasks,
		"p2p_links":   m.srv.p2p.ListLinks(),
	}
	if m.srv.campaign != nil {
		if data, err := m.srv.campaign.Export(); err == nil {
			var campaignExport map[string]interface{}
			if json.Unmarshal(data, &campaignExport) == nil {
				export["campaign"] = campaignExport
			}
		}
	}
	if m.srv.cfg.Workspace != "" {
		writeC2State(m.srv.cfg.Workspace, "campaign_export", map[string]interface{}{
			"sessions": len(sessions), "tasks": len(tasks),
		})
	}
	jsonResp(w, export)
}

// --- Loot Management ---

func (m *ManagementAPI) handleListLoot(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	category := r.URL.Query().Get("category")
	items, err := m.srv.loot.ListLoot(category)
	if err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	type lootEntry struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Category   string `json:"category"`
		Size       int64  `json:"size"`
		SHA256     string `json:"sha256"`
		SourceHost string `json:"source_host"`
		SourcePath string `json:"source_path"`
		SessionID  string `json:"session_id"`
	}
	entries := make([]lootEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, lootEntry{
			ID: item.Id, Name: item.Name, Category: item.Category,
			Size: item.Size, SHA256: item.Sha256, SourceHost: item.SourceHost,
			SourcePath: item.SourcePath, SessionID: item.SessionId,
		})
	}
	jsonResp(w, map[string]interface{}{"loot": entries, "count": len(entries)})
}

func (m *ManagementAPI) handleGetLoot(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		jsonResp(w, map[string]string{"error": "id required"})
		return
	}
	item, err := m.srv.loot.GetLootByID(id)
	if err != nil {
		jsonResp(w, map[string]string{"error": "loot not found: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+item.Name+"\"")
	w.Write(item.Data)
}

func (m *ManagementAPI) handleStoreLoot(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermCampaignManage) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name       string `json:"name"`
		Category   string `json:"category"`
		Data       string `json:"data"`
		SourceHost string `json:"source_host"`
		SourcePath string `json:"source_path"`
		SessionID  string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	rawData, _ := base64.StdEncoding.DecodeString(req.Data)
	id := fmt.Sprintf("loot-%d", time.Now().UnixNano())
	lf := &pb.LootFile{
		Id: id, Name: req.Name, Category: req.Category,
		Data: rawData, Size: int64(len(rawData)),
		SourceHost: req.SourceHost, SourcePath: req.SourcePath, SessionId: req.SessionID,
		CapturedAt: timestamppb.Now(),
	}
	if err := m.srv.loot.StoreLoot(lf); err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, map[string]interface{}{"success": true, "id": id})
}

func (m *ManagementAPI) handleLootStats(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	stats, err := m.srv.loot.GetLootStats()
	if err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, map[string]interface{}{"stats": stats})
}

func (m *ManagementAPI) handleListScreenshots(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	items, err := m.srv.loot.ListLoot("screenshot")
	if err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	type ssEntry struct {
		ID         string `json:"id"`
		SessionID  string `json:"session_id"`
		SourceHost string `json:"source_host"`
		Size       int64  `json:"size"`
		CapturedAt string `json:"captured_at"`
	}
	entries := make([]ssEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, ssEntry{
			ID: item.Id, SessionID: item.SessionId,
			SourceHost: item.SourceHost, Size: item.Size,
		})
	}
	jsonResp(w, map[string]interface{}{"screenshots": entries, "count": len(entries)})
}

func (m *ManagementAPI) handleGetScreenshot(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionList) {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		jsonResp(w, map[string]string{"error": "id required"})
		return
	}
	item, err := m.srv.loot.GetLootByID(id)
	if err != nil {
		jsonResp(w, map[string]string{"error": "screenshot not found"})
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", "inline; filename=\""+item.Name+"\"")
	w.Write(item.Data)
}

// --- Session Notes / Labels ---

func (m *ManagementAPI) handleSessionNote(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	if r.Method == http.MethodGet {
		id := r.URL.Query().Get("id")
		sess, err := m.srv.sessions.GetSession(id)
		if err != nil {
			jsonResp(w, map[string]string{"error": err.Error()})
			return
		}
		jsonResp(w, map[string]interface{}{"id": id, "note": sess.Note})
		return
	}
	var req struct {
		ID   string `json:"id"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	sess, err := m.srv.sessions.GetSession(req.ID)
	if err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	sess.Note = req.Note
	go m.srv.sessions.PersistSession(sess)
	jsonResp(w, map[string]interface{}{"success": true, "id": req.ID, "note": req.Note})
}

func (m *ManagementAPI) handleSessionLabel(w http.ResponseWriter, r *http.Request) {
	if !m.requirePerm(w, r, auth.PermSessionInteract) {
		return
	}
	if r.Method == http.MethodGet {
		id := r.URL.Query().Get("id")
		sess, err := m.srv.sessions.GetSession(id)
		if err != nil {
			jsonResp(w, map[string]string{"error": err.Error()})
			return
		}
		jsonResp(w, map[string]interface{}{"id": id, "labels": sess.Labels})
		return
	}
	var req struct {
		ID     string   `json:"id"`
		Labels []string `json:"labels"`
		Add    string   `json:"add"`
		Remove string   `json:"remove"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	sess, err := m.srv.sessions.GetSession(req.ID)
	if err != nil {
		jsonResp(w, map[string]string{"error": err.Error()})
		return
	}
	if req.Labels != nil {
		sess.Labels = req.Labels
	} else if req.Add != "" {
		for _, l := range sess.Labels {
			if l == req.Add {
				jsonResp(w, map[string]interface{}{"success": true, "labels": sess.Labels})
				return
			}
		}
		sess.Labels = append(sess.Labels, req.Add)
	} else if req.Remove != "" {
		filtered := make([]string, 0, len(sess.Labels))
		for _, l := range sess.Labels {
			if l != req.Remove {
				filtered = append(filtered, l)
			}
		}
		sess.Labels = filtered
	}
	go m.srv.sessions.PersistSession(sess)
	jsonResp(w, map[string]interface{}{"success": true, "id": req.ID, "labels": sess.Labels})
}

// StartManagementAPI starts the HTTP management server on the given address
func (s *Server) StartManagementAPI(addr string, useTLS bool) error {
	api := NewManagementAPI(s, s.logger.Named("mgmt"))
	server := &http.Server{
		Addr:    addr,
		Handler: api.AuthenticatedHandler(),
	}
	if useTLS {
		cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load management TLS cert: %w", err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}
	go func() {
		s.logger.Info("management API listening", zap.String("addr", addr), zap.Bool("tls", useTLS))
		var err error
		if useTLS {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("management API error", zap.Error(err))
		}
	}()
	return nil
}

// Suppress unused import
var _ = fmt.Sprintf
