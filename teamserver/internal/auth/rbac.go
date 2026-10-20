package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// Role defines operator permission levels
type Role string

const (
	RoleAdmin    Role = "admin"    // Full access to all operations
	RoleOperator Role = "operator" // Standard operator - can task sessions, build payloads
	RoleViewer   Role = "viewer"   // Read-only - can view sessions, tasks, findings
	RoleBuilder  Role = "builder"  // Can generate payloads but not task sessions
)

// Permission represents a specific action that can be authorized
type Permission string

const (
	PermSessionList     Permission = "session.list"
	PermSessionInteract Permission = "session.interact"
	PermSessionKill     Permission = "session.kill"
	PermTaskCreate      Permission = "task.create"
	PermTaskView        Permission = "task.view"
	PermListenerCreate  Permission = "listener.create"
	PermListenerStop    Permission = "listener.stop"
	PermBuildImplant    Permission = "build.implant"
	PermBuildStager     Permission = "build.stager" // C stager via MinGW builder
	PermBuildStage      Permission = "builds.stage" // encrypted stage-1 download
	PermCredView        Permission = "cred.view"
	PermCredAdd         Permission = "cred.add"
	PermCampaignManage  Permission = "campaign.manage"
	PermAdminUsers      Permission = "admin.users"
	PermAdminConfig     Permission = "admin.config"
)

// RolePermissions maps roles to their allowed permissions
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermSessionList, PermSessionInteract, PermSessionKill,
		PermTaskCreate, PermTaskView,
		PermListenerCreate, PermListenerStop,
		PermBuildImplant, PermBuildStager, PermBuildStage,
		PermCredView, PermCredAdd,
		PermCampaignManage,
		PermAdminUsers, PermAdminConfig,
	},
	RoleOperator: {
		PermSessionList, PermSessionInteract, PermSessionKill,
		PermTaskCreate, PermTaskView,
		PermListenerCreate, PermListenerStop,
		PermBuildImplant, PermBuildStager, PermBuildStage,
		PermCredView, PermCredAdd,
		PermCampaignManage,
	},
	RoleViewer: {
		PermSessionList,
		PermTaskView,
		PermCredView,
	},
	RoleBuilder: {
		PermBuildImplant, PermBuildStager, PermBuildStage,
		PermSessionList,
	},
}

// Operator represents an authenticated user of the C2
type Operator struct {
	ID              string
	Name            string
	Role            Role
	CertFingerprint string
	Active          bool
}

// AuthManager handles operator authentication and authorization
type AuthManager struct {
	mu        sync.RWMutex
	operators map[string]*Operator // keyed by cert fingerprint
	logger    *zap.Logger
}

func NewAuthManager(logger *zap.Logger) *AuthManager {
	return &AuthManager{
		operators: make(map[string]*Operator),
		logger:    logger.Named("auth"),
	}
}

// RegisterOperator adds a new operator with their certificate fingerprint
func (am *AuthManager) RegisterOperator(name string, role Role, certPEM []byte) (*Operator, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	fingerprint := fmt.Sprintf("%x", cert.AuthorityKeyId)
	if fingerprint == "" {
		// Use subject key identifier or serial as fallback
		fingerprint = fmt.Sprintf("%x", cert.SerialNumber.Bytes())
	}

	op := &Operator{
		ID:              fmt.Sprintf("op-%s", name),
		Name:            name,
		Role:            role,
		CertFingerprint: fingerprint,
		Active:          true,
	}

	am.operators[fingerprint] = op
	am.logger.Info("operator registered",
		zap.String("name", name),
		zap.String("role", string(role)),
	)
	return op, nil
}

// Authenticate identifies an operator by their client certificate
func (am *AuthManager) Authenticate(certPEM []byte) (*Operator, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	fingerprint := fmt.Sprintf("%x", cert.AuthorityKeyId)
	if fingerprint == "" {
		fingerprint = fmt.Sprintf("%x", cert.SerialNumber.Bytes())
	}

	op, ok := am.operators[fingerprint]
	if !ok {
		return nil, fmt.Errorf("unknown operator certificate")
	}

	if !op.Active {
		return nil, fmt.Errorf("operator account disabled")
	}

	return op, nil
}

// Authorize checks if an operator has a specific permission
func (am *AuthManager) Authorize(op *Operator, perm Permission) bool {
	if op == nil {
		return false
	}

	permissions, ok := RolePermissions[op.Role]
	if !ok {
		return false
	}

	for _, p := range permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// RegisterOperatorByName adds a bootstrap operator without certificate (dev/API-key mode).
func (am *AuthManager) RegisterOperatorByName(name string, role Role) *Operator {
	am.mu.Lock()
	defer am.mu.Unlock()

	op := &Operator{
		ID:              fmt.Sprintf("op-%s", name),
		Name:            name,
		Role:            role,
		CertFingerprint: fmt.Sprintf("name:%s", name),
		Active:          true,
	}
	am.operators[op.CertFingerprint] = op
	am.logger.Info("operator registered by name",
		zap.String("name", name),
		zap.String("role", string(role)),
	)
	return op
}

// AuthenticateByName identifies an operator by name (for bootstrapping)
func (am *AuthManager) AuthenticateByName(name string) (*Operator, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, op := range am.operators {
		if op.Name == name && op.Active {
			return op, nil
		}
	}
	return nil, fmt.Errorf("operator not found: %s", name)
}

// ListOperators returns all registered operators
func (am *AuthManager) ListOperators() []*Operator {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var ops []*Operator
	for _, op := range am.operators {
		ops = append(ops, op)
	}
	return ops
}

// DeactivateOperator disables an operator account
func (am *AuthManager) DeactivateOperator(name string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	for _, op := range am.operators {
		if op.Name == name {
			op.Active = false
			am.logger.Info("operator deactivated", zap.String("name", name))
			return nil
		}
	}
	return fmt.Errorf("operator not found: %s", name)
}
