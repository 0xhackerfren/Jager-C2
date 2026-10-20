package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/auth"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
)

// TaskRequest is the structured operator task submission format.
type TaskRequest struct {
	SessionID string          `json:"session_id"`
	Type      json.RawMessage `json:"type"`
	Args      []string        `json:"args,omitempty"`
	RawData   string          `json:"data,omitempty"`
	Timeout   int             `json:"timeout,omitempty"`
}

func (m *ManagementAPI) operatorID(r *http.Request) string {
	if op, ok := r.Context().Value(operatorCtxKey).(*auth.Operator); ok && op != nil {
		return op.Name
	}
	return "system"
}

func (m *ManagementAPI) auditLog(r *http.Request, action, sessionID, taskID, details string) {
	if m.srv.campaign != nil {
		m.srv.campaign.LogAction(m.operatorID(r), action, sessionID, taskID, details)
	}
}

func parseTaskType(raw json.RawMessage) (pb.TaskType, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("type required")
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return pb.TaskType(n), nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return taskTypeFromString(s), nil
	}
	return 0, fmt.Errorf("invalid task type")
}

func taskTypeFromString(s string) pb.TaskType {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "TASK_")
	switch s {
	case "SHELL":
		return pb.TaskType_TASK_SHELL
	case "POWERSHELL":
		return pb.TaskType_TASK_POWERSHELL
	case "EXECUTE":
		return pb.TaskType_TASK_EXECUTE
	case "LS":
		return pb.TaskType_TASK_LS
	case "CD":
		return pb.TaskType_TASK_CD
	case "PWD":
		return pb.TaskType_TASK_PWD
	case "CAT":
		return pb.TaskType_TASK_CAT
	case "PS":
		return pb.TaskType_TASK_PS
	case "SLEEP":
		return pb.TaskType_TASK_SLEEP
	case "EXIT":
		return pb.TaskType_TASK_EXIT
	default:
		if n, err := strconv.Atoi(s); err == nil {
			return pb.TaskType(n)
		}
		return pb.TaskType_TASK_UNKNOWN
	}
}

func buildTaskRequestData(taskType pb.TaskType, args []string, rawData string, timeout int) ([]byte, error) {
	if rawData != "" {
		decoded, err := base64.StdEncoding.DecodeString(rawData)
		if err != nil {
			return []byte(rawData), nil
		}
		return decoded, nil
	}

	switch taskType {
	case pb.TaskType_TASK_SHELL, pb.TaskType_TASK_POWERSHELL:
		cmd := strings.Join(args, " ")
		if len(args) == 1 {
			cmd = args[0]
		}
		if timeout == 0 {
			timeout = 60
		}
		return json.Marshal(map[string]interface{}{
			"command":          cmd,
			"timeout_seconds": timeout,
		})
	case pb.TaskType_TASK_EXECUTE:
		payload := map[string]interface{}{"hidden": true}
		if len(args) > 0 {
			payload["path"] = args[0]
			if len(args) > 1 {
				payload["args"] = args[1:]
			}
		}
		if timeout > 0 {
			payload["timeout_seconds"] = timeout
		}
		return json.Marshal(payload)
	case pb.TaskType_TASK_LS, pb.TaskType_TASK_CD, pb.TaskType_TASK_CAT:
		path := "."
		if len(args) > 0 {
			path = args[0]
		}
		return json.Marshal(map[string]string{"path": path})
	default:
		if len(args) > 0 {
			return []byte(strings.Join(args, " ")), nil
		}
		return nil, nil
	}
}

func taskResponseJSON(task *pb.Task) map[string]interface{} {
	out := map[string]interface{}{
		"task_id":   task.Id,
		"state":     task.State.String(),
		"output":    string(task.ResponseData),
		"exit_code": task.ExitCode,
	}
	if task.Error != "" {
		out["error"] = task.Error
	}
	return out
}
