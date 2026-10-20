package jagerpb

import "google.golang.org/protobuf/types/known/timestamppb"

// TaskType enumerates the types of tasks an implant can execute.
// Values MUST match tasks.proto TaskType enum exactly.
type TaskType int32

const (
	TaskType_TASK_UNKNOWN TaskType = 0

	// Core
	TaskType_TASK_SLEEP       TaskType = 1
	TaskType_TASK_EXIT        TaskType = 2
	TaskType_TASK_SELF_DELETE TaskType = 3

	// Execution
	TaskType_TASK_SHELL            TaskType = 10
	TaskType_TASK_POWERSHELL       TaskType = 11
	TaskType_TASK_EXECUTE          TaskType = 12
	TaskType_TASK_EXECUTE_ASSEMBLY TaskType = 13
	TaskType_TASK_BOF              TaskType = 14
	TaskType_TASK_SHELLCODE        TaskType = 15
	TaskType_TASK_INLINE_EXECUTE   TaskType = 16

	// Filesystem
	TaskType_TASK_LS        TaskType = 20
	TaskType_TASK_CD        TaskType = 21
	TaskType_TASK_PWD       TaskType = 22
	TaskType_TASK_CAT       TaskType = 23
	TaskType_TASK_UPLOAD    TaskType = 24
	TaskType_TASK_DOWNLOAD  TaskType = 25
	TaskType_TASK_RM        TaskType = 26
	TaskType_TASK_MKDIR     TaskType = 27
	TaskType_TASK_CP        TaskType = 28
	TaskType_TASK_MV        TaskType = 29
	TaskType_TASK_TIMESTOMP TaskType = 30

	// Process
	TaskType_TASK_PS           TaskType = 40
	TaskType_TASK_KILL_PROCESS TaskType = 41
	TaskType_TASK_SPAWN        TaskType = 42
	TaskType_TASK_INJECT       TaskType = 43
	TaskType_TASK_MIGRATE      TaskType = 44

	// Network
	TaskType_TASK_IFCONFIG    TaskType = 50
	TaskType_TASK_NETSTAT     TaskType = 51
	TaskType_TASK_PORTSCAN    TaskType = 52
	TaskType_TASK_SOCKS_START TaskType = 53
	TaskType_TASK_SOCKS_STOP  TaskType = 54
	TaskType_TASK_PORTFWD_ADD TaskType = 55
	TaskType_TASK_PORTFWD_RM  TaskType = 56

	// Credential
	TaskType_TASK_TOKEN_STEAL      TaskType = 60
	TaskType_TASK_MAKE_TOKEN       TaskType = 61
	TaskType_TASK_REVERT_TOKEN     TaskType = 62
	TaskType_TASK_HASHDUMP         TaskType = 63
	TaskType_TASK_KERBEROS_TICKETS TaskType = 64
	TaskType_TASK_DPAPI            TaskType = 65
	TaskType_TASK_LOGON_USER       TaskType = 66

	// Evasion
	TaskType_TASK_SLEEP_MASK       TaskType = 70
	TaskType_TASK_UNHOOK           TaskType = 71
	TaskType_TASK_PATCH_ETW        TaskType = 72
	TaskType_TASK_PATCH_AMSI       TaskType = 73
	TaskType_TASK_MODULE_STOMP     TaskType = 74
	TaskType_TASK_THREADLESS_INJECT TaskType = 75

	// Lateral movement
	TaskType_TASK_LATERAL_PSEXEC  TaskType = 80
	TaskType_TASK_LATERAL_WMI     TaskType = 81
	TaskType_TASK_LATERAL_DCOM    TaskType = 82
	TaskType_TASK_LATERAL_WINRM   TaskType = 83
	TaskType_TASK_LATERAL_SCHTASK TaskType = 84

	// Persistence
	TaskType_TASK_PERSIST_REGISTRY     TaskType = 90
	TaskType_TASK_PERSIST_SERVICE      TaskType = 91
	TaskType_TASK_PERSIST_SCHTASK      TaskType = 92
	TaskType_TASK_PERSIST_COM          TaskType = 93
	TaskType_TASK_PERSIST_DLL_SIDELOAD TaskType = 94

	// Collection
	TaskType_TASK_SCREENSHOT    TaskType = 100
	TaskType_TASK_KEYLOG_START  TaskType = 101
	TaskType_TASK_KEYLOG_STOP   TaskType = 102
	TaskType_TASK_CLIPBOARD     TaskType = 103
	TaskType_TASK_BROWSER_CREDS TaskType = 104

	// Pivoting
	TaskType_TASK_P2P_LISTEN  TaskType = 110
	TaskType_TASK_P2P_CONNECT TaskType = 111
	TaskType_TASK_P2P_RELAY   TaskType = 112

	// Defense evasion (extended)
	TaskType_TASK_DEFENSE_CLEAR_EVENTLOG TaskType = 113
	TaskType_TASK_ARP_SCAN               TaskType = 114

	// Reverse port forwarding
	TaskType_TASK_RPORTFWD_ADD    TaskType = 115
	TaskType_TASK_RPORTFWD_REMOVE TaskType = 116
)

func (t TaskType) String() string {
	switch t {
	case TaskType_TASK_UNKNOWN:
		return "UNKNOWN"
	case TaskType_TASK_SLEEP:
		return "SLEEP"
	case TaskType_TASK_EXIT:
		return "EXIT"
	case TaskType_TASK_SELF_DELETE:
		return "SELF_DELETE"
	case TaskType_TASK_SHELL:
		return "SHELL"
	case TaskType_TASK_POWERSHELL:
		return "POWERSHELL"
	case TaskType_TASK_EXECUTE:
		return "EXECUTE"
	case TaskType_TASK_EXECUTE_ASSEMBLY:
		return "EXECUTE_ASSEMBLY"
	case TaskType_TASK_BOF:
		return "BOF"
	case TaskType_TASK_SHELLCODE:
		return "SHELLCODE"
	case TaskType_TASK_INLINE_EXECUTE:
		return "INLINE_EXECUTE"
	case TaskType_TASK_LS:
		return "LS"
	case TaskType_TASK_CD:
		return "CD"
	case TaskType_TASK_PWD:
		return "PWD"
	case TaskType_TASK_CAT:
		return "CAT"
	case TaskType_TASK_UPLOAD:
		return "UPLOAD"
	case TaskType_TASK_DOWNLOAD:
		return "DOWNLOAD"
	case TaskType_TASK_RM:
		return "RM"
	case TaskType_TASK_MKDIR:
		return "MKDIR"
	case TaskType_TASK_PS:
		return "PS"
	case TaskType_TASK_KILL_PROCESS:
		return "KILL_PROCESS"
	case TaskType_TASK_SPAWN:
		return "SPAWN"
	case TaskType_TASK_INJECT:
		return "INJECT"
	case TaskType_TASK_MIGRATE:
		return "MIGRATE"
	case TaskType_TASK_IFCONFIG:
		return "IFCONFIG"
	case TaskType_TASK_NETSTAT:
		return "NETSTAT"
	case TaskType_TASK_PORTSCAN:
		return "PORTSCAN"
	case TaskType_TASK_SOCKS_START:
		return "SOCKS_START"
	case TaskType_TASK_SOCKS_STOP:
		return "SOCKS_STOP"
	case TaskType_TASK_PORTFWD_ADD:
		return "PORTFWD_ADD"
	case TaskType_TASK_PORTFWD_RM:
		return "PORTFWD_RM"
	case TaskType_TASK_SCREENSHOT:
		return "SCREENSHOT"
	case TaskType_TASK_P2P_LISTEN:
		return "P2P_LISTEN"
	case TaskType_TASK_P2P_CONNECT:
		return "P2P_CONNECT"
	case TaskType_TASK_P2P_RELAY:
		return "P2P_RELAY"
	case TaskType_TASK_DEFENSE_CLEAR_EVENTLOG:
		return "DEFENSE_CLEAR_EVENTLOG"
	case TaskType_TASK_ARP_SCAN:
		return "ARP_SCAN"
	case TaskType_TASK_RPORTFWD_ADD:
		return "RPORTFWD_ADD"
	case TaskType_TASK_RPORTFWD_REMOVE:
		return "RPORTFWD_REMOVE"
	case TaskType_TASK_THREADLESS_INJECT:
		return "THREADLESS_INJECT"
	default:
		return "UNKNOWN"
	}
}

// TaskState tracks the lifecycle of a task.
// Values MUST match tasks.proto TaskState enum exactly.
type TaskState int32

const (
	TaskState_TASK_STATE_QUEUED    TaskState = 0
	TaskState_TASK_STATE_SENT      TaskState = 1
	TaskState_TASK_STATE_RUNNING   TaskState = 2
	TaskState_TASK_STATE_COMPLETED TaskState = 3
	TaskState_TASK_STATE_FAILED    TaskState = 4
	TaskState_TASK_STATE_CANCELLED TaskState = 5
)

func (s TaskState) String() string {
	switch s {
	case TaskState_TASK_STATE_QUEUED:
		return "QUEUED"
	case TaskState_TASK_STATE_SENT:
		return "SENT"
	case TaskState_TASK_STATE_RUNNING:
		return "RUNNING"
	case TaskState_TASK_STATE_COMPLETED:
		return "COMPLETED"
	case TaskState_TASK_STATE_FAILED:
		return "FAILED"
	case TaskState_TASK_STATE_CANCELLED:
		return "CANCELLED"
	default:
		return "UNKNOWN"
	}
}

// Task represents a command/action queued for an implant
type Task struct {
	Id           string                 `json:"id"`
	SessionId    string                 `json:"session_id"`
	Type         TaskType               `json:"type"`
	State        TaskState              `json:"state"`
	RequestData  []byte                 `json:"request_data,omitempty"`
	ResponseData []byte                 `json:"response_data,omitempty"`
	Error        string                 `json:"error,omitempty"`
	ExitCode     int32                  `json:"exit_code,omitempty"`
	CreatedAt    *timestamppb.Timestamp `json:"created_at,omitempty"`
	SentAt       *timestamppb.Timestamp `json:"sent_at,omitempty"`
	CompletedAt  *timestamppb.Timestamp `json:"completed_at,omitempty"`
	CreatedBy    string                 `json:"created_by,omitempty"`
}

// Request/Response types
type TaskRequest struct {
	SessionId string   `json:"session_id"`
	Type      TaskType `json:"type"`
	Data      []byte   `json:"data,omitempty"`
	Request   *Request `json:"request,omitempty"`
}

type TaskResponse struct {
	Task   *Task   `json:"task,omitempty"`
	Status *Status `json:"status,omitempty"`
}

type TasksListRequest struct {
	SessionId   string    `json:"session_id,omitempty"`
	FilterState TaskState `json:"filter_state"`
	Limit       uint32    `json:"limit"`
}

type TasksListResponse struct {
	Tasks []*Task `json:"tasks"`
}

type TaskCancelRequest struct {
	TaskId string `json:"task_id"`
}

// TunnelFrame carries bidirectional data over the C2 channel
type TunnelOp int32

const (
	TunnelOp_OPEN  TunnelOp = 0
	TunnelOp_DATA  TunnelOp = 1
	TunnelOp_CLOSE TunnelOp = 2
)

type TunnelFrame struct {
	ChannelID  uint32   `json:"channel_id"`
	Op         TunnelOp `json:"op"`
	Payload    []byte   `json:"payload,omitempty"`
	TargetHost string   `json:"target_host,omitempty"`
	TargetPort uint32   `json:"target_port,omitempty"`
	SessionID  string   `json:"session_id,omitempty"`
}
