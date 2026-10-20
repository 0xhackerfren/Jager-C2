package server

import (
	"crypto/subtle"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/auth"
	"go.uber.org/zap"
)

// OperatorKey associates an API key with an operator identity and role.
type OperatorKey struct {
	Operator string    `json:"operator"`
	Key      string    `json:"key"`
	Role     string    `json:"role"` // admin, operator, readonly
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitempty"`
}

// APIKeyStore holds per-operator API keys for REST and gRPC authentication.
type APIKeyStore struct {
	mu     sync.RWMutex
	keys   map[string]*OperatorKey // key -> OperatorKey
	logger *zap.Logger
}

func NewAPIKeyStore(logger *zap.Logger) *APIKeyStore {
	return &APIKeyStore{
		keys:   make(map[string]*OperatorKey),
		logger: logger,
	}
}

// LoadDefault seeds the store from JAGER_MGMT_API_KEY and optional operator-keys.json.
func (s *APIKeyStore) LoadDefault(workspace, dbPath string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if data, err := os.ReadFile(operatorKeysFilePath(workspace, dbPath)); err == nil {
		var entries []OperatorKey
		if json.Unmarshal(data, &entries) == nil {
			for i := range entries {
				entry := entries[i]
				if entry.Key == "" {
					continue
				}
				s.keys[entry.Key] = &entry
			}
		}
	}

	if len(s.keys) > 0 {
		for _, op := range s.keys {
			_ = os.Setenv("JAGER_MGMT_API_KEY", op.Key)
			return op.Key
		}
	}

	key := strings.TrimSpace(os.Getenv("JAGER_MGMT_API_KEY"))
	if key == "" {
		key = EnsureMgmtAPIKey(workspace, dbPath, s.logger)
	}

	role := "admin"
	if r := os.Getenv("JAGER_OPERATOR_ROLE"); r != "" {
		role = r
	}
	operator := "default"
	if n := os.Getenv("JAGER_OPERATOR_NAME"); n != "" {
		operator = n
	}

	s.keys[key] = &OperatorKey{
		Operator: operator,
		Key:      key,
		Role:     role,
		Created:  time.Now(),
	}
	return key
}

func (s *APIKeyStore) Add(op OperatorKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[op.Key] = &op
}

// Validate checks an API key and returns the associated operator metadata.
func (s *APIKeyStore) Validate(key string) (*OperatorKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for storedKey, op := range s.keys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(storedKey)) != 1 {
			continue
		}
		if !op.Expires.IsZero() && time.Now().After(op.Expires) {
			return nil, false
		}
		return op, true
	}
	return nil, false
}

func (s *APIKeyStore) RoleForKey(key string) auth.Role {
	op, ok := s.Validate(key)
	if !ok {
		return ""
	}
	return authRoleFromString(op.Role)
}

func authRoleFromString(role string) auth.Role {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return auth.RoleAdmin
	case "operator":
		return auth.RoleOperator
	case "readonly", "viewer":
		return auth.RoleViewer
	case "builder":
		return auth.RoleBuilder
	default:
		return auth.RoleOperator
	}
}

func (s *APIKeyStore) allOperators() []*OperatorKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*OperatorKey, 0, len(s.keys))
	for _, op := range s.keys {
		out = append(out, op)
	}
	return out
}

func operatorKeysFilePath(workspace, dbPath string) string {
	if workspace != "" {
		return filepath.Join(workspace, "data", "operator-keys.json")
	}
	if dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "operator-keys.json")
	}
	return filepath.Join("data", "operator-keys.json")
}
