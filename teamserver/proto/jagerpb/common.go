package jagerpb

import "google.golang.org/protobuf/types/known/timestamppb"

// Transport protocol types
type Transport int32

const (
	Transport_TRANSPORT_HTTPS Transport = 0
	Transport_TRANSPORT_DNS   Transport = 1
	Transport_TRANSPORT_TCP   Transport = 2
	Transport_TRANSPORT_SMB   Transport = 3
)

func (t Transport) String() string {
	switch t {
	case Transport_TRANSPORT_HTTPS:
		return "HTTPS"
	case Transport_TRANSPORT_DNS:
		return "DNS"
	case Transport_TRANSPORT_TCP:
		return "TCP"
	case Transport_TRANSPORT_SMB:
		return "SMB"
	default:
		return "UNKNOWN"
	}
}

// OSType represents operating system types
type OSType int32

const (
	OSType_OS_UNKNOWN OSType = 0
	OSType_OS_WINDOWS OSType = 1
	OSType_OS_LINUX   OSType = 2
	OSType_OS_MACOS   OSType = 3
)

func (o OSType) String() string {
	switch o {
	case OSType_OS_WINDOWS:
		return "Windows"
	case OSType_OS_LINUX:
		return "Linux"
	case OSType_OS_MACOS:
		return "macOS"
	default:
		return "Unknown"
	}
}

// Request is a generic request wrapper with operator context
type Request struct {
	Operator  string `json:"operator,omitempty"`
	RequestId string `json:"request_id,omitempty"`
}

func (r *Request) GetOperator() string {
	if r == nil {
		return ""
	}
	return r.Operator
}

// Status is the generic response status
type Status struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Ensure timestamppb is used (dependency for other files)
var _ = timestamppb.Now
