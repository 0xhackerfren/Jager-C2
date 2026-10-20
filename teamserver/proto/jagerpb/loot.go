package jagerpb

import "google.golang.org/protobuf/types/known/timestamppb"

// CredType enumerates credential types
type CredType int32

const (
	CredType_CRED_UNKNOWN    CredType = 0
	CredType_CRED_PASSWORD   CredType = 1
	CredType_CRED_NTLM_HASH CredType = 2
	CredType_CRED_KERBEROS   CredType = 3
	CredType_CRED_CERTIFICATE CredType = 4
	CredType_CRED_SSH_KEY    CredType = 5
	CredType_CRED_TOKEN      CredType = 6
)

// OS enumerates operating system types
type OS int32

const (
	OS_UNKNOWN OS = 0
	OS_WINDOWS OS = 1
	OS_LINUX   OS = 2
	OS_MACOS   OS = 3
)

// Credential represents a captured credential
type Credential struct {
	Id         string                 `json:"id"`
	Username   string                 `json:"username"`
	Domain     string                 `json:"domain,omitempty"`
	Type       CredType               `json:"type"`
	Data       string                 `json:"data"`
	Source     string                 `json:"source,omitempty"`
	SourceHost string                 `json:"source_host,omitempty"`
	SessionId  string                 `json:"session_id,omitempty"`
	CapturedAt *timestamppb.Timestamp `json:"captured_at,omitempty"`
	Validated  bool                   `json:"validated"`
	Notes      string                 `json:"notes,omitempty"`
}

// Target represents a discovered/compromised host
type Target struct {
	Id          string `json:"id"`
	Hostname    string `json:"hostname,omitempty"`
	Ip          string `json:"ip"`
	Domain      string `json:"domain,omitempty"`
	Os          OS     `json:"os"`
	OsVersion   string `json:"os_version,omitempty"`
	AccessLevel string `json:"access_level,omitempty"`
	Compromised bool   `json:"compromised"`
	Notes       string `json:"notes,omitempty"`
}

// Finding represents a security finding
type Finding struct {
	Id          string                 `json:"id"`
	Title       string                 `json:"title"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description,omitempty"`
	TargetId    string                 `json:"target_id,omitempty"`
	TechniqueId string                 `json:"technique_id,omitempty"`
	Evidence    string                 `json:"evidence,omitempty"`
	FoundAt     *timestamppb.Timestamp `json:"found_at,omitempty"`
}

// Pivot represents an active network pivot
type Pivot struct {
	Id              string    `json:"id"`
	SourceSessionId string    `json:"source_session_id"`
	TargetHost      string    `json:"target_host"`
	Transport       Transport `json:"transport"`
	PipeName        string    `json:"pipe_name,omitempty"`
	Port            int32     `json:"port,omitempty"`
	Active          bool      `json:"active"`
}

// LootFile represents a stored loot artifact
type LootFile struct {
	Id         string                 `json:"id"`
	Name       string                 `json:"name"`
	Category   string                 `json:"category"`
	Data       []byte                 `json:"data,omitempty"`
	Size       int64                  `json:"size"`
	Sha256     string                 `json:"sha256,omitempty"`
	SourceHost string                 `json:"source_host,omitempty"`
	SourcePath string                 `json:"source_path,omitempty"`
	SessionId  string                 `json:"session_id,omitempty"`
	CapturedAt *timestamppb.Timestamp `json:"captured_at,omitempty"`
}

// AccessLog records access events
type AccessLog struct {
	SessionId string                 `json:"session_id"`
	TargetId  string                 `json:"target_id"`
	Method    string                 `json:"method"`
	Status    string                 `json:"status"`
	Timestamp *timestamppb.Timestamp `json:"timestamp,omitempty"`
}

// TechniqueLog records MITRE ATT&CK technique usage
type TechniqueLog struct {
	TechniqueId   string                 `json:"technique_id"`
	TechniqueName string                 `json:"technique_name"`
	Tactic        string                 `json:"tactic,omitempty"`
	SessionId     string                 `json:"session_id,omitempty"`
	TargetId      string                 `json:"target_id,omitempty"`
	ToolName      string                 `json:"tool_name,omitempty"`
	Success       bool                   `json:"success"`
	Timestamp     *timestamppb.Timestamp `json:"timestamp,omitempty"`
}

// EngagementSummary provides overall engagement statistics
type EngagementSummary struct {
	TotalSessions      uint32   `json:"total_sessions"`
	ActiveSessions     uint32   `json:"active_sessions"`
	TotalBeacons       uint32   `json:"total_beacons"`
	ActiveBeacons      uint32   `json:"active_beacons"`
	TotalTargets       uint32   `json:"total_targets"`
	CompromisedTargets uint32   `json:"compromised_targets"`
	TotalCredentials   uint32   `json:"total_credentials"`
	TotalFindings      uint32   `json:"total_findings"`
	TechniquesUsed     uint32   `json:"techniques_used"`
	ActiveListeners    []string `json:"active_listeners,omitempty"`
}

// Request/Response types for loot operations
type AddCredentialRequest struct {
	Credential *Credential `json:"credential"`
}

type ListCredentialsRequest struct {
	DomainFilter string   `json:"domain_filter,omitempty"`
	TypeFilter   CredType `json:"type_filter"`
}

type CredentialsResponse struct {
	Credentials []*Credential `json:"credentials"`
}

type AddTargetRequest struct {
	Target *Target `json:"target"`
}

type ListTargetsRequest struct {
	CompromisedOnly bool `json:"compromised_only"`
}

type TargetsResponse struct {
	Targets []*Target `json:"targets"`
}

type AddFindingRequest struct {
	Finding *Finding `json:"finding"`
}

type ListFindingsRequest struct {
	SeverityFilter string `json:"severity_filter,omitempty"`
}

type FindingsResponse struct {
	Findings []*Finding `json:"findings"`
}

type AddPivotRequest struct {
	Pivot *Pivot `json:"pivot"`
}

type ListPivotsRequest struct {
	ActiveOnly bool `json:"active_only"`
}

type PivotsResponse struct {
	Pivots []*Pivot `json:"pivots"`
}

type StoreLootRequest struct {
	Loot *LootFile `json:"loot"`
}

type ListLootRequest struct {
	Category string `json:"category,omitempty"`
}

type LootResponse struct {
	Items []*LootFile `json:"items"`
}

type LogAccessRequest struct {
	Entry *AccessLog `json:"entry"`
}

type LogTechniqueRequest struct {
	Entry *TechniqueLog `json:"entry"`
}

type SummaryRequest struct{}
