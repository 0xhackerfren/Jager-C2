package tasks

import (
	"strings"
	"testing"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func setupQueue(t *testing.T) (*Queue, string, string) {
	t.Helper()

	sessionMgr := sessions.NewManager(zap.NewNop())
	q := NewQueue(zap.NewNop(), sessionMgr)

	sessionA := "sess-a"
	sessionB := "sess-b"
	sessionMgr.RegisterSession(&pb.ImplantRegistration{
		ImplantId: sessionA,
		Hostname:  "host-a",
		Username:  "user-a",
		Transport: pb.Transport_TRANSPORT_HTTPS,
	}, nil)
	sessionMgr.RegisterSession(&pb.ImplantRegistration{
		ImplantId: sessionB,
		Hostname:  "host-b",
		Username:  "user-b",
		Transport: pb.Transport_TRANSPORT_HTTPS,
	}, nil)

	return q, sessionA, sessionB
}

func TestEnqueueDequeue(t *testing.T) {
	q, sessionA, _ := setupQueue(t)

	task := &pb.Task{
		Id:        "task-1",
		SessionId: sessionA,
		Type:      pb.TaskType_TASK_SHELL,
		State:     pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt: timestamppb.Now(),
	}

	if err := q.Enqueue(task); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	dequeued := q.Dequeue(sessionA, 10)
	if len(dequeued) != 1 {
		t.Fatalf("expected 1 task, got %d", len(dequeued))
	}
	if dequeued[0].Id != "task-1" {
		t.Fatalf("expected task-1, got %s", dequeued[0].Id)
	}
}

func TestCompleteWrongSession(t *testing.T) {
	q, sessionA, sessionB := setupQueue(t)

	task := &pb.Task{
		Id:        "task-wrong-session",
		SessionId: sessionA,
		Type:      pb.TaskType_TASK_SHELL,
		State:     pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt: timestamppb.Now(),
	}
	if err := q.Enqueue(task); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	err := q.Complete("task-wrong-session", sessionB, []byte("output"), "")
	if err == nil {
		t.Fatal("expected error completing task for wrong session")
	}
	if !strings.Contains(err.Error(), sessionA) {
		t.Fatalf("expected error to mention owning session, got %v", err)
	}
}

func TestListFilterByState(t *testing.T) {
	q, sessionA, _ := setupQueue(t)

	queued := &pb.Task{
		Id:        "task-queued",
		SessionId: sessionA,
		Type:      pb.TaskType_TASK_SHELL,
		State:     pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt: timestamppb.Now(),
	}
	done := &pb.Task{
		Id:        "task-done",
		SessionId: sessionA,
		Type:      pb.TaskType_TASK_SHELL,
		State:     pb.TaskState_TASK_STATE_COMPLETED,
		CreatedAt: timestamppb.Now(),
	}
	q.mu.Lock()
	q.tasks[queued.Id] = queued
	q.tasks[done.Id] = done
	q.mu.Unlock()

	queuedOnly := q.List(sessionA, pb.TaskState_TASK_STATE_QUEUED, 0)
	if len(queuedOnly) != 1 || queuedOnly[0].Id != "task-queued" {
		t.Fatalf("expected only queued task, got %d tasks", len(queuedOnly))
	}

	all := q.List(sessionA, pb.TaskState(-1), 0)
	if len(all) != 2 {
		t.Fatalf("expected all tasks with no filter, got %d", len(all))
	}
}

func TestCancelTask(t *testing.T) {
	q, sessionA, _ := setupQueue(t)

	task := &pb.Task{
		Id:        "task-cancel",
		SessionId: sessionA,
		Type:      pb.TaskType_TASK_SHELL,
		State:     pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt: timestamppb.Now(),
	}
	if err := q.Enqueue(task); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if err := q.Cancel("task-cancel"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	got, err := q.Get("task-cancel")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != pb.TaskState_TASK_STATE_CANCELLED {
		t.Fatalf("expected CANCELLED, got %v", got.State)
	}

	pending := q.Dequeue(sessionA, 10)
	if len(pending) != 0 {
		t.Fatalf("cancelled task should not be pending, got %d", len(pending))
	}
}

func TestRedeliverSentTasks(t *testing.T) {
	q, sessionA, _ := setupQueue(t)

	task := &pb.Task{
		Id:        "task-redeliver",
		SessionId: sessionA,
		Type:      pb.TaskType_TASK_SHELL,
		State:     pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt: timestamppb.Now(),
	}
	if err := q.Enqueue(task); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	dequeued := q.Dequeue(sessionA, 10)
	if len(dequeued) != 1 || dequeued[0].State != pb.TaskState_TASK_STATE_SENT {
		t.Fatalf("expected sent task, got %+v", dequeued)
	}

	q.RedeliverSentTasks(sessionA)
	again := q.Dequeue(sessionA, 10)
	if len(again) != 1 {
		t.Fatalf("expected redelivered task, got %d", len(again))
	}
}

func TestPurgeSessionTasks(t *testing.T) {
	q, sessionA, _ := setupQueue(t)

	task := &pb.Task{
		Id:        "task-purge",
		SessionId: sessionA,
		Type:      pb.TaskType_TASK_SHELL,
		State:     pb.TaskState_TASK_STATE_QUEUED,
		CreatedAt: timestamppb.Now(),
	}
	if err := q.Enqueue(task); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	q.PurgeSessionTasks(sessionA)
	if _, err := q.Get("task-purge"); err == nil {
		t.Fatal("purged task should be removed")
	}
}
