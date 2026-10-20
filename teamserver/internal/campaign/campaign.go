package campaign

import (
	"encoding/json"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp  time.Time `json:"ts"`
	OperatorID string    `json:"operator_id"`
	Action     string    `json:"action"`
	SessionID  string    `json:"session_id,omitempty"`
	TaskID     string    `json:"task_id,omitempty"`
	Details    string    `json:"details,omitempty"`
}

type Campaign struct {
	mu      sync.RWMutex
	Name    string       `json:"name"`
	Created time.Time    `json:"created"`
	Audit   []AuditEntry `json:"audit"`
}

type Manager struct {
	mu        sync.RWMutex
	campaigns map[string]*Campaign
	audit     []AuditEntry // global audit trail
}

func NewManager() *Manager {
	return &Manager{
		campaigns: make(map[string]*Campaign),
	}
}

func (m *Manager) LogAction(operatorID, action, sessionID, taskID, details string) {
	entry := AuditEntry{
		Timestamp:  time.Now(),
		OperatorID: operatorID,
		Action:     action,
		SessionID:  sessionID,
		TaskID:     taskID,
		Details:    details,
	}
	m.mu.Lock()
	m.audit = append(m.audit, entry)
	m.mu.Unlock()
}

func (m *Manager) GetAuditTrail(limit int) []AuditEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.audit) {
		limit = len(m.audit)
	}
	start := len(m.audit) - limit
	if start < 0 {
		start = 0
	}
	result := make([]AuditEntry, limit)
	copy(result, m.audit[start:])
	return result
}

func (m *Manager) Export() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return json.MarshalIndent(struct {
		Campaigns map[string]*Campaign `json:"campaigns"`
		Audit     []AuditEntry         `json:"audit"`
	}{m.campaigns, m.audit}, "", "  ")
}
