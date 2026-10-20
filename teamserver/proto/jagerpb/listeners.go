package jagerpb

import "google.golang.org/protobuf/types/known/timestamppb"

// HTTPSListenerConfig holds HTTPS-specific listener settings
type HTTPSListenerConfig struct {
	CertPem      string `json:"cert_pem,omitempty"`
	KeyPem       string `json:"key_pem,omitempty"`
	TlsCert      string `json:"tls_cert,omitempty"`
	TlsKey       string `json:"tls_key,omitempty"`
	ServerHeader string `json:"server_header,omitempty"`
	Domain       string `json:"domain,omitempty"`
}

// DNSListenerConfig holds DNS-specific listener settings
type DNSListenerConfig struct {
	Domains []string `json:"domains,omitempty"`
	Domain  string   `json:"domain,omitempty"`
}

// TCPListenerConfig holds raw TCP listener settings
type TCPListenerConfig struct {
	UseTLS bool `json:"use_tls,omitempty"`
}

// SMBListenerConfig holds SMB named pipe settings
type SMBListenerConfig struct {
	PipeName string `json:"pipe_name,omitempty"`
}

// ListenerConfig is the configuration for a C2 listener
type ListenerConfig struct {
	Id        string                 `json:"id"`
	Name      string                 `json:"name,omitempty"`
	Transport Transport              `json:"transport"`
	BindHost  string                 `json:"bind_host"`
	BindPort  uint32                 `json:"bind_port"`
	StartedAt *timestamppb.Timestamp `json:"started_at,omitempty"`

	// Transport-specific config (only one set)
	Https *HTTPSListenerConfig `json:"https,omitempty"`
	Dns   *DNSListenerConfig   `json:"dns,omitempty"`
	Tcp   *TCPListenerConfig   `json:"tcp,omitempty"`
	Smb   *SMBListenerConfig   `json:"smb,omitempty"`
}

func (c *ListenerConfig) GetHttps() *HTTPSListenerConfig {
	if c == nil {
		return nil
	}
	return c.Https
}

func (c *ListenerConfig) GetDns() *DNSListenerConfig {
	if c == nil {
		return nil
	}
	return c.Dns
}

func (c *ListenerConfig) GetTcp() *TCPListenerConfig {
	if c == nil {
		return nil
	}
	return c.Tcp
}

func (c *ListenerConfig) GetSmb() *SMBListenerConfig {
	if c == nil {
		return nil
	}
	return c.Smb
}

// MalleableProfile defines traffic shaping for a listener
type MalleableProfile struct {
	Name        string   `json:"name"`
	UserAgent   string   `json:"user_agent,omitempty"`
	GetUris     []string `json:"get_uris,omitempty"`
	PostUris    []string `json:"post_uris,omitempty"`
	Headers     []string `json:"headers,omitempty"`
	ServerAttrs []string `json:"server_attrs,omitempty"`
}

// Request/Response types for listener management
type StartListenerRequest struct {
	Config *ListenerConfig `json:"config"`
}

type ListenerResponse struct {
	Listener *ListenerConfig `json:"listener,omitempty"`
	Status   *Status         `json:"status,omitempty"`
}

type StopListenerRequest struct {
	ListenerId string `json:"listener_id"`
}

type ListListenersRequest struct{}

type ListenersResponse struct {
	Listeners []*ListenerConfig `json:"listeners"`
}

type SetProfileRequest struct {
	ListenerId string            `json:"listener_id"`
	Profile    *MalleableProfile `json:"profile"`
}
