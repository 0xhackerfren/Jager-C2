package tasks

import (
	"database/sql"
	"fmt"
	"time"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SetDB enables task queue persistence to SQLite.
func (q *Queue) SetDB(db *sql.DB) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.db = db
}

// PersistTask writes or updates a task record in SQLite.
func (q *Queue) PersistTask(task *pb.Task) {
	if q.db == nil || task == nil {
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	createdAt := now
	if task.CreatedAt != nil {
		createdAt = task.CreatedAt.AsTime().Format(time.RFC3339)
	}

	var sentAt, completedAt sql.NullString
	if task.SentAt != nil {
		sentAt = sql.NullString{String: task.SentAt.AsTime().Format(time.RFC3339), Valid: true}
	}
	if task.CompletedAt != nil {
		completedAt = sql.NullString{String: task.CompletedAt.AsTime().Format(time.RFC3339), Valid: true}
	}

	_, err := q.db.Exec(`
		INSERT INTO task_queue (id, session_id, type, state, request_data,
			response_data, error, exit_code, created_at, sent_at, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			state = excluded.state,
			response_data = excluded.response_data,
			error = excluded.error,
			exit_code = excluded.exit_code,
			sent_at = excluded.sent_at,
			completed_at = excluded.completed_at
	`,
		task.Id, task.SessionId, int32(task.Type), int32(task.State),
		task.RequestData, task.ResponseData, task.Error, task.ExitCode,
		createdAt, sentAt, completedAt,
	)
	if err != nil {
		q.logger.Error("failed to persist task",
			zap.String("task_id", task.Id), zap.Error(err))
	}
}

// LoadPersistedTasks restores QUEUED and SENT tasks from SQLite on startup.
// SENT tasks are marked as retriable (back to QUEUED).
func (q *Queue) LoadPersistedTasks() (loaded int, err error) {
	if q.db == nil {
		return 0, nil
	}

	rows, err := q.db.Query(`
		SELECT id, session_id, type, state, request_data, error, exit_code,
			created_at, sent_at
		FROM task_queue
		WHERE state IN (?, ?)
	`, int32(pb.TaskState_TASK_STATE_QUEUED), int32(pb.TaskState_TASK_STATE_SENT))
	if err != nil {
		return 0, fmt.Errorf("query persisted tasks: %w", err)
	}
	defer rows.Close()

	q.mu.Lock()
	defer q.mu.Unlock()

	for rows.Next() {
		var (
			id, sessionID, errMsg, createdAtStr string
			taskType, state, exitCode           int32
			requestData                         []byte
			sentAt                              sql.NullString
		)

		err = rows.Scan(&id, &sessionID, &taskType, &state, &requestData,
			&errMsg, &exitCode, &createdAtStr, &sentAt)
		if err != nil {
			q.logger.Error("scan persisted task", zap.Error(err))
			continue
		}

		if !q.sessions.SessionExists(sessionID) {
			continue
		}

		createdAt, _ := time.Parse(time.RFC3339, createdAtStr)

		task := &pb.Task{
			Id:          id,
			SessionId:   sessionID,
			Type:        pb.TaskType(taskType),
			State:       pb.TaskState_TASK_STATE_QUEUED,
			RequestData: requestData,
			Error:       errMsg,
			ExitCode:    exitCode,
			CreatedAt:   timestamppb.New(createdAt),
		}

		q.tasks[id] = task
		q.pending[sessionID] = append(q.pending[sessionID], task)
		loaded++
	}

	if loaded > 0 {
		q.logger.Info("restored persisted tasks", zap.Int("count", loaded))
	}
	return loaded, rows.Err()
}

// PurgeCompleted removes completed/failed/cancelled tasks older than maxAge from SQLite.
func (q *Queue) PurgeCompleted(maxAge time.Duration) (int64, error) {
	if q.db == nil {
		return 0, nil
	}

	cutoff := time.Now().Add(-maxAge).UTC().Format(time.RFC3339)
	result, err := q.db.Exec(`
		DELETE FROM task_queue
		WHERE state IN (?, ?, ?)
		AND completed_at < ?
	`,
		int32(pb.TaskState_TASK_STATE_COMPLETED),
		int32(pb.TaskState_TASK_STATE_FAILED),
		int32(pb.TaskState_TASK_STATE_CANCELLED),
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
