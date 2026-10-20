package redirectors

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	StatusActive = "active"
	StatusDown   = "down"
	StatusBurned = "burned"
)

// Redirector represents a proxy between implants and the teamserver.
type Redirector struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ExternalIP string    `json:"external_ip"`
	InternalIP string    `json:"internal_ip"` // Where it connects to teamserver
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"` // https, dns, smb
	Status     string    `json:"status"`   // active, down, burned
	LastSeen   time.Time `json:"last_seen"`
	BytesSent  int64     `json:"bytes_sent"`
	BytesRecv  int64     `json:"bytes_recv"`
	ListenerID string    `json:"listener_id"` // Associated listener
}

// Manager tracks redirector infrastructure and generates proxy configs.
type Manager struct {
	mu          sync.RWMutex
	redirectors map[string]*Redirector
	logger      *zap.Logger
}

// NewManager constructs a redirector manager.
func NewManager(logger *zap.Logger) *Manager {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Manager{
		redirectors: make(map[string]*Redirector),
		logger:      logger,
	}
}

// Add registers a redirector (generates ID when empty).
func (m *Manager) Add(r *Redirector) error {
	if r == nil {
		return fmt.Errorf("redirector is nil")
	}
	if r.Name == "" {
		return fmt.Errorf("name required")
	}
	if r.InternalIP == "" {
		return fmt.Errorf("internal_ip required")
	}
	if r.Port <= 0 {
		return fmt.Errorf("port required")
	}
	if r.Protocol == "" {
		r.Protocol = "https"
	}
	if r.Status == "" {
		r.Status = StatusActive
	}
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	r.LastSeen = time.Now().UTC()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.redirectors[r.ID] = cloneRedirector(r)
	m.logger.Info("redirector added",
		zap.String("id", r.ID),
		zap.String("name", r.Name),
		zap.String("external_ip", r.ExternalIP),
	)
	return nil
}

// Remove deletes a redirector by ID.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.redirectors[id]; !ok {
		return fmt.Errorf("redirector not found: %s", id)
	}
	delete(m.redirectors, id)
	m.logger.Info("redirector removed", zap.String("id", id))
	return nil
}

// Get returns a redirector by ID.
func (m *Manager) Get(id string) (*Redirector, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.redirectors[id]
	if !ok {
		return nil, false
	}
	return cloneRedirector(r), true
}

// List returns all registered redirectors.
func (m *Manager) List() []*Redirector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Redirector, 0, len(m.redirectors))
	for _, r := range m.redirectors {
		out = append(out, cloneRedirector(r))
	}
	return out
}

// HealthCheck probes each non-burned redirector and updates status.
func (m *Manager) HealthCheck() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, r := range m.redirectors {
		if r.Status == StatusBurned {
			continue
		}
		target := net.JoinHostPort(r.ExternalIP, fmt.Sprintf("%d", r.Port))
		if r.ExternalIP == "" {
			target = net.JoinHostPort(r.InternalIP, fmt.Sprintf("%d", r.Port))
		}
		conn, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err != nil {
			r.Status = StatusDown
			m.logger.Debug("redirector health check failed",
				zap.String("id", id),
				zap.String("target", target),
				zap.Error(err),
			)
			continue
		}
		_ = conn.Close()
		r.Status = StatusActive
		r.LastSeen = time.Now().UTC()
	}
}

// MarkBurned marks a redirector as compromised.
func (m *Manager) MarkBurned(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.redirectors[id]
	if !ok {
		return fmt.Errorf("redirector not found: %s", id)
	}
	r.Status = StatusBurned
	m.logger.Warn("redirector marked burned", zap.String("id", id), zap.String("name", r.Name))
	return nil
}

// GenerateNginxConfig produces an nginx reverse-proxy config for a redirector.
func (m *Manager) GenerateNginxConfig(listenerPort int, uriPath string, userAgent string) string {
	if listenerPort <= 0 {
		listenerPort = 443
	}
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	paths := splitPaths(uriPath)
	if len(paths) == 0 {
		paths = []string{"/api/v1/checkin", "/api/v1/register", "/api/v1/result", "/api/v1/tunnel", "/api/v1/stage"}
	}

	var b strings.Builder
	fmt.Fprintf(&b, `# Jager-C2 redirector — nginx reverse proxy
# Only forwards malleable-profile URIs with matching User-Agent; 404 otherwise.

upstream jager_teamserver {
    server 127.0.0.1:%d;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Decoy: normal web server for non-matching traffic
    location / {
        return 404;
    }

`, listenerPort)

	ua := nginxQuote(userAgent)
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		fmt.Fprintf(&b, `    location = %s {
        if ($http_user_agent != %s) {
            return 404;
        }
        proxy_pass https://jager_teamserver;
        proxy_http_version 1.1;
        # Verify teamserver TLS cert; set proxy_ssl_verify off only for lab/self-signed backends.
        proxy_ssl_verify on;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }

`, p, ua)
	}

	b.WriteString("}\n")
	return b.String()
}

// GenerateApacheConfig produces an Apache mod_rewrite reverse-proxy config.
func (m *Manager) GenerateApacheConfig(listenerPort int, uriPath string, userAgent string) string {
	if listenerPort <= 0 {
		listenerPort = 443
	}
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	paths := splitPaths(uriPath)
	if len(paths) == 0 {
		paths = []string{"/api/v1/checkin", "/api/v1/register", "/api/v1/result", "/api/v1/tunnel", "/api/v1/stage"}
	}

	var b strings.Builder
	fmt.Fprintf(&b, `# Jager-C2 redirector — Apache mod_rewrite reverse proxy
<VirtualHost *:443>
    ServerName redirector.local

    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/redirector.crt
    SSLCertificateKeyFile /etc/ssl/private/redirector.key
    SSLProtocol           all -SSLv3 -TLSv1 -TLSv1.1

    ProxyPreserveHost On
    ProxyRequests Off
    SSLProxyEngine On
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off

    RewriteEngine On

    # Require matching User-Agent (404 otherwise)
    RewriteCond %%{HTTP_USER_AGENT} !^%s$ [NC]
    RewriteRule ^ - [R=404,L]

`, apacheEscapeRegex(userAgent))

	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		escaped := apacheEscapeRegex(p)
		fmt.Fprintf(&b, `    RewriteRule ^%s$ https://127.0.0.1:%d%s [P,L]
`, escaped, listenerPort, p)
	}

	b.WriteString(`
    # Default decoy
    RewriteRule ^ - [R=404,L]
</VirtualHost>
`)
	return b.String()
}

func splitPaths(uriPath string) []string {
	if uriPath == "" {
		return nil
	}
	parts := strings.Split(uriPath, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func nginxQuote(s string) string {
	return fmt.Sprintf(`"%s"`, strings.ReplaceAll(s, `"`, `\"`))
}

func apacheEscapeRegex(s string) string {
	replacer := strings.NewReplacer(
		".", `\.`,
		"+", `\+`,
		"*", `\*`,
		"?", `\?`,
		"(", `\(`,
		")", `\)`,
		"[", `\[`,
		"]", `\]`,
		"{", `\{`,
		"}", `\}`,
		"|", `\|`,
		"^", `\^`,
		"$", `\$`,
	)
	return replacer.Replace(s)
}

func cloneRedirector(r *Redirector) *Redirector {
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}
