package tasks

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/events"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const MaxTaskRetries = 3

type Queue struct {
	mu          sync.RWMutex
	tasks       map[string]*pb.Task
	pending     map[string][]*pb.Task // session_id -> pending tasks
	retryCounts map[string]int
	sessions    *sessions.Manager
	logger      *zap.Logger
	events      *events.Bus
	db          *sql.DB
}

func NewQueue(logger *zap.Logger, sessions *sessions.Manager) *Queue {
	return &Queue{
		tasks:       make(map[string]*pb.Task),
		pending:     make(map[string][]*pb.Task),
		retryCounts: make(map[string]int),
		sessions:    sessions,
		logger:      logger,
	}
}

func (q *Queue) SetEventBus(bus *events.Bus) {
	q.events = bus
}

func (q *Queue) Enqueue(task *pb.Task) error {
	if !q.sessions.SessionExists(task.SessionId) {
		return fmt.Errorf("session not found: %s", task.SessionId)
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	q.tasks[task.Id] = task
	q.pending[task.SessionId] = append(q.pending[task.SessionId], task)

	q.logger.Info("task enqueued",
		zap.String("task_id", task.Id),
		zap.String("session_id", task.SessionId),
		zap.String("type", task.Type.String()),
	)
	if q.events != nil {
		q.events.Publish(events.Event{
			Type:      events.EventTaskQueued,
			SessionID: task.SessionId,
			TaskID:    task.Id,
			Data:      map[string]interface{}{"type": task.Type.String()},
		})
	}
	go q.PersistTask(task)
	return nil
}

func (q *Queue) Get(taskID string) (*pb.Task, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	task, ok := q.tasks[taskID]
	if !ok {
		return nil, fmt.Errorf("task not found: %s", taskID)
	}
	return task, nil
}

// Dequeue returns pending tasks for a session (called by implant on check-in)
func (q *Queue) Dequeue(sessionID string, maxTasks int) []*pb.Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	totalPending := 0
	for sid, p := range q.pending {
		if len(p) > 0 {
			totalPending += len(p)
			q.logger.Debug("dequeue: pending snapshot",
				zap.String("queued_session", sid),
				zap.Int("count", len(p)),
				zap.String("requested_session", sessionID),
				zap.Bool("match", sid == sessionID))
		}
	}

	pending := q.pending[sessionID]
	if len(pending) == 0 {
		return nil
	}

	count := maxTasks
	if count > len(pending) || count <= 0 {
		count = len(pending)
	}

	dequeued := pending[:count]
	q.pending[sessionID] = pending[count:]

	for _, t := range dequeued {
		t.State = pb.TaskState_TASK_STATE_SENT
		t.SentAt = timestamppb.Now()
		if q.events != nil {
			q.events.Publish(events.Event{
				Type:      events.EventTaskSent,
				SessionID: sessionID,
				TaskID:    t.Id,
			})
		}
	}

	return dequeued
}

// RedeliverSentTasks re-queues tasks that were sent but never completed.
func (q *Queue) RedeliverSentTasks(sessionID string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, t := range q.tasks {
		if t.SessionId != sessionID || t.State != pb.TaskState_TASK_STATE_SENT {
			continue
		}
		q.retryCounts[t.Id]++
		if q.retryCounts[t.Id] > MaxTaskRetries {
			t.State = pb.TaskState_TASK_STATE_FAILED
			t.Error = "max retries exceeded"
			continue
		}
		t.State = pb.TaskState_TASK_STATE_QUEUED
		q.pending[sessionID] = append(q.pending[sessionID], t)
		q.logger.Info("task redelivered",
			zap.String("task_id", t.Id),
			zap.String("session_id", sessionID),
			zap.Int("retry", q.retryCounts[t.Id]),
		)
	}
}

// PurgeSessionTasks cancels pending and in-flight tasks for a dead session.
func (q *Queue) PurgeSessionTasks(sessionID string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for id, t := range q.tasks {
		if t.SessionId != sessionID {
			continue
		}
		if t.State == pb.TaskState_TASK_STATE_QUEUED ||
			t.State == pb.TaskState_TASK_STATE_SENT {
			t.State = pb.TaskState_TASK_STATE_CANCELLED
			delete(q.tasks, id)
			delete(q.retryCounts, id)
		}
	}
	delete(q.pending, sessionID)
}

// Complete marks a task as done with response data
func (q *Queue) Complete(taskID string, sessionID string, responseData []byte, errMsg string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	task, ok := q.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	if task.SessionId != sessionID {
		return fmt.Errorf("task %s belongs to session %s, not %s", taskID, task.SessionId, sessionID)
	}

	task.CompletedAt = timestamppb.Now()
	task.ResponseData = responseData
	task.ExitCode = parseExitCode(responseData)

	if errMsg != "" {
		task.State = pb.TaskState_TASK_STATE_FAILED
		task.Error = errMsg
	} else {
		task.State = pb.TaskState_TASK_STATE_COMPLETED
	}

	q.logger.Info("task completed",
		zap.String("task_id", taskID),
		zap.String("state", task.State.String()),
		zap.Int32("exit_code", task.ExitCode),
	)
	if q.events != nil {
		evType := events.EventTaskCompleted
		if task.State == pb.TaskState_TASK_STATE_FAILED {
			evType = events.EventTaskFailed
		}
		q.events.Publish(events.Event{
			Type:      evType,
			SessionID: sessionID,
			TaskID:    taskID,
			Data: map[string]interface{}{
				"exit_code":     task.ExitCode,
				"error":         errMsg,
				"type":          int32(task.Type),
				"response_data": responseData,
			},
		})
	}
	go q.PersistTask(task)
	return nil
}

func parseExitCode(responseData []byte) int32 {
	if len(responseData) == 0 {
		return 0
	}
	var shellResp struct {
		ExitCode int32 `json:"exit_code"`
	}
	if json.Unmarshal(responseData, &shellResp) == nil && shellResp.ExitCode != 0 {
		return shellResp.ExitCode
	}
	var generic struct {
		ExitCode int32 `json:"exit_code"`
		Code     int32 `json:"code"`
	}
	if json.Unmarshal(responseData, &generic) == nil {
		if generic.ExitCode != 0 {
			return generic.ExitCode
		}
		if generic.Code != 0 {
			return generic.Code
		}
	}
	return 0
}

func (q *Queue) Cancel(taskID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	task, ok := q.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	if task.State == pb.TaskState_TASK_STATE_COMPLETED || task.State == pb.TaskState_TASK_STATE_FAILED {
		return fmt.Errorf("cannot cancel completed task")
	}

	task.State = pb.TaskState_TASK_STATE_CANCELLED
	// Remove from pending queue
	pending := q.pending[task.SessionId]
	for i, t := range pending {
		if t.Id == taskID {
			q.pending[task.SessionId] = append(pending[:i], pending[i+1:]...)
			break
		}
	}
	return nil
}

func (q *Queue) List(sessionID string, filterState pb.TaskState, limit uint32) []*pb.Task {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var result []*pb.Task
	for _, t := range q.tasks {
		if sessionID != "" && t.SessionId != sessionID {
			continue
		}
		if int32(filterState) >= 0 && t.State != filterState {
			continue
		}
		result = append(result, t)
		if limit > 0 && uint32(len(result)) >= limit {
			break
		}
	}
	return result
}

func (q *Queue) QueueSleepChange(sessionID string, interval, jitter uint32) error {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint32(payload[0:4], interval)
	binary.LittleEndian.PutUint32(payload[4:8], jitter)
	task := &pb.Task{
		Id:          fmt.Sprintf("sleep-%s-%d", sessionID, interval),
		SessionId:   sessionID,
		Type:        pb.TaskType_TASK_SLEEP,
		State:       pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt:   timestamppb.Now(),
		RequestData: payload,
	}
	return q.Enqueue(task)
}
