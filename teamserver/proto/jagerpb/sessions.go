package jagerpb

import "google.golang.org/protobuf/types/known/timestamppb"

// ImplantRegistration holds the initial registration data from an implant
type ImplantRegistration struct {
	ImplantId   string    `json:"implant_id"`
	BuildId     string    `json:"build_id,omitempty"`
	Hostname    string    `json:"hostname"`
	Username    string    `json:"username"`
	Uid         string    `json:"uid,omitempty"`
	Os          any       `json:"os,omitempty"`
	Arch        any       `json:"arch,omitempty"`
	Pid         int32     `json:"pid,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
	OsVersion   string    `json:"os_version,omitempty"`
	Elevated    bool      `json:"elevated"`
	InternalIp  string    `json:"internal_ip,omitempty"`
	ExternalIp  string    `json:"external_ip,omitempty"`
	Transport   Transport `json:"transport"`
	Domain      string    `json:"domain,omitempty"`
}

// Session represents an interactive implant connection
type Session struct {
	Id              string                 `json:"id"`
	Registration    *ImplantRegistration   `json:"registration,omitempty"`
	LastCheckin     *timestamppb.Timestamp `json:"last_checkin,omitempty"`
	Alive           bool                   `json:"alive"`
	ActiveTransport Transport              `json:"active_transport"`
	RemoteAddr      string                 `json:"remote_addr,omitempty"`
	Note            string                 `json:"note,omitempty"`
	Labels          []string               `json:"labels,omitempty"`
}

func (s *Session) GetHostname() string {
	if s != nil && s.Registration != nil {
		return s.Registration.Hostname
	}
	return ""
}

// Beacon represents a periodic check-in implant
type Beacon struct {
	Id              string                 `json:"id"`
	Registration    *ImplantRegistration   `json:"registration,omitempty"`
	LastCheckin     *timestamppb.Timestamp `json:"last_checkin,omitempty"`
	NextCheckin     *timestamppb.Timestamp `json:"next_checkin,omitempty"`
	IntervalSeconds uint32                 `json:"interval_seconds"`
	JitterPercent   uint32                 `json:"jitter_percent"`
	Alive           bool                   `json:"alive"`
	ActiveTransport Transport              `json:"active_transport"`
	RemoteAddr      string                 `json:"remote_addr,omitempty"`
	Note            string                 `json:"note,omitempty"`
	Labels          []string               `json:"labels,omitempty"`
}

// Request/Response types for gRPC
type SessionsRequest struct {
	AliveOnly bool `json:"alive_only"`
}

type SessionsResponse struct {
	Sessions []*Session `json:"sessions"`
}

type BeaconsRequest struct {
	AliveOnly bool `json:"alive_only"`
}

type BeaconsResponse struct {
	Beacons []*Beacon `json:"beacons"`
}

type InteractRequest struct {
	SessionId string `json:"session_id"`
}

type SessionResponse struct {
	Session *Session `json:"session,omitempty"`
	Status  *Status  `json:"status,omitempty"`
}

type KillRequest struct {
	Id    string `json:"id"`
	Force bool   `json:"force"`
}

type RenameRequest struct {
	Id      string `json:"id"`
	NewName string `json:"new_name"`
}

type SleepRequest struct {
	Id              string `json:"id"`
	IntervalSeconds uint32 `json:"interval_seconds"`
	JitterPercent   uint32 `json:"jitter_percent"`
}
