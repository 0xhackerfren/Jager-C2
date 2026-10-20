package pivot

import (
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// P2PLink represents a known P2P connection between two implants
type P2PLink struct {
	ParentSession string `json:"parent_session"`
	ChildSession  string `json:"child_session"`
	Transport     string `json:"transport"` // "pipe" or "tcp"
	PipeName      string `json:"pipe_name,omitempty"`
	Port          int    `json:"port,omitempty"`
}

// P2PManager tracks the implant connectivity graph for multi-hop pivoting.
// When an implant has no direct C2 connectivity, its traffic is relayed
// through parent implants that do have connectivity.
type P2PManager struct {
	mu    sync.RWMutex
	links []P2PLink
	// parentOf maps child session -> parent session for routing
	parentOf map[string]string
	logger   *zap.Logger
}

func NewP2PManager(logger *zap.Logger) *P2PManager {
	return &P2PManager{
		parentOf: make(map[string]string),
		logger:   logger.Named("p2p"),
	}
}

// AddLink records a new P2P connection between two implants
func (pm *P2PManager) AddLink(parent, child, transport, pipeName string, port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.links = append(pm.links, P2PLink{
		ParentSession: parent,
		ChildSession:  child,
		Transport:     transport,
		PipeName:      pipeName,
		Port:          port,
	})
	pm.parentOf[child] = parent

	pm.logger.Info("P2P link established",
		zap.String("parent", parent),
		zap.String("child", child),
		zap.String("transport", transport))
}

// RemoveLink removes a P2P connection
func (pm *P2PManager) RemoveLink(parent, child string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	found := false
	var remaining []P2PLink
	for _, l := range pm.links {
		if l.ParentSession == parent && l.ChildSession == child {
			found = true
			continue
		}
		remaining = append(remaining, l)
	}
	if !found {
		return fmt.Errorf("link not found: %s -> %s", parent, child)
	}

	pm.links = remaining
	delete(pm.parentOf, child)
	return nil
}

// GetRoute returns the chain of sessions to reach a target implant
// from the teamserver. If the implant has direct connectivity, returns
// a single-element slice. If it's behind P2P links, returns the full chain.
func (pm *P2PManager) GetRoute(sessionID string) []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var chain []string
	current := sessionID

	for i := 0; i < 10; i++ {
		chain = append([]string{current}, chain...)
		parent, ok := pm.parentOf[current]
		if !ok {
			break
		}
		current = parent
	}
	return chain
}

// ListLinks returns all known P2P links
func (pm *P2PManager) ListLinks() []P2PLink {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	out := make([]P2PLink, len(pm.links))
	copy(out, pm.links)
	return out
}
