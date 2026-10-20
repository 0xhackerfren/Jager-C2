package pivot

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// PivotInfo describes an active pivot for API responses
type PivotInfo struct {
	ID         int       `json:"id"`
	Type       string    `json:"type"`
	SessionID  string    `json:"session_id"`
	BindPort   int       `json:"bind_port"`
	Remote     string    `json:"remote,omitempty"`
	StartedAt  time.Time `json:"started_at"`
}

// Manager coordinates all active pivots (SOCKS relays and port forwards)
type Manager struct {
	mu       sync.Mutex
	tunnels  *TunnelManager
	nextID   int32
	socks    map[int]*SocksRelay
	portfwds map[int]*RPortFwd
	logger   *zap.Logger
}

func NewManager(tm *TunnelManager, logger *zap.Logger) *Manager {
	return &Manager{
		tunnels:  tm,
		socks:    make(map[int]*SocksRelay),
		portfwds: make(map[int]*RPortFwd),
		logger:   logger.Named("pivot-mgr"),
	}
}

func (m *Manager) Tunnels() *TunnelManager {
	return m.tunnels
}

func (m *Manager) allocID() int {
	return int(atomic.AddInt32(&m.nextID, 1))
}

// StartSocksRelay starts an operator-facing SOCKS5 relay for a session
func (m *Manager) StartSocksRelay(sessionID string, port int) (*PivotInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for port conflict
	for _, sr := range m.socks {
		if sr.Port() == port {
			return nil, fmt.Errorf("port %d already in use by SOCKS relay", port)
		}
	}
	for _, pf := range m.portfwds {
		if pf.BindPort() == port {
			return nil, fmt.Errorf("port %d already in use by port forward", port)
		}
	}

	id := m.allocID()
	relay := NewSocksRelay(sessionID, port, m.tunnels, m.logger)
	if err := relay.Start(); err != nil {
		return nil, err
	}

	m.socks[id] = relay

	return &PivotInfo{
		ID:        id,
		Type:      "socks",
		SessionID: sessionID,
		BindPort:  port,
		StartedAt: time.Now(),
	}, nil
}

// StopSocksRelay stops a SOCKS relay by pivot ID
func (m *Manager) StopSocksRelay(pivotID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sr, ok := m.socks[pivotID]
	if !ok {
		return fmt.Errorf("socks relay %d not found", pivotID)
	}
	sr.Stop()
	delete(m.socks, pivotID)
	return nil
}

// StartPortForward starts a reverse port forward relay
func (m *Manager) StartPortForward(sessionID string, bindPort int, remoteHost string, remotePort int) (*PivotInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for port conflict
	for _, sr := range m.socks {
		if sr.Port() == bindPort {
			return nil, fmt.Errorf("port %d already in use by SOCKS relay", bindPort)
		}
	}
	for _, pf := range m.portfwds {
		if pf.BindPort() == bindPort {
			return nil, fmt.Errorf("port %d already in use by port forward", bindPort)
		}
	}

	id := m.allocID()
	rpf := NewRPortFwd(id, sessionID, bindPort, remoteHost, remotePort, m.tunnels, m.logger)
	if err := rpf.Start(); err != nil {
		return nil, err
	}

	m.portfwds[id] = rpf

	return &PivotInfo{
		ID:        id,
		Type:      "portfwd",
		SessionID: sessionID,
		BindPort:  bindPort,
		Remote:    rpf.Remote(),
		StartedAt: time.Now(),
	}, nil
}

// StopPortForward stops a port forward by pivot ID
func (m *Manager) StopPortForward(pivotID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pf, ok := m.portfwds[pivotID]
	if !ok {
		return fmt.Errorf("port forward %d not found", pivotID)
	}
	pf.Stop()
	delete(m.portfwds, pivotID)
	return nil
}

// StopPivot stops any pivot by ID (socks or portfwd)
func (m *Manager) StopPivot(pivotID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if sr, ok := m.socks[pivotID]; ok {
		sr.Stop()
		delete(m.socks, pivotID)
		return nil
	}
	if pf, ok := m.portfwds[pivotID]; ok {
		pf.Stop()
		delete(m.portfwds, pivotID)
		return nil
	}
	return fmt.Errorf("pivot %d not found", pivotID)
}

// ListPivots returns all active pivots
func (m *Manager) ListPivots() []PivotInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []PivotInfo
	for id, sr := range m.socks {
		out = append(out, PivotInfo{
			ID:        id,
			Type:      "socks",
			SessionID: sr.sessionID,
			BindPort:  sr.port,
		})
	}
	for id, pf := range m.portfwds {
		out = append(out, PivotInfo{
			ID:        id,
			Type:      "portfwd",
			SessionID: pf.sessionID,
			BindPort:  pf.bindPort,
			Remote:    pf.Remote(),
		})
	}
	return out
}

// StopAllForSession stops all pivots for a session (used on session cleanup)
func (m *Manager) StopAllForSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, sr := range m.socks {
		if sr.sessionID == sessionID {
			sr.Stop()
			delete(m.socks, id)
		}
	}
	for id, pf := range m.portfwds {
		if pf.sessionID == sessionID {
			pf.Stop()
			delete(m.portfwds, id)
		}
	}
}
