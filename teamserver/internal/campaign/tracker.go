package campaign

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Phase represents a campaign execution phase
type Phase string

const (
	PhaseRecon      Phase = "recon"
	PhaseInitAccess Phase = "initial_access"
	PhaseExecution  Phase = "execution"
	PhasePersist    Phase = "persistence"
	PhasePrivEsc    Phase = "privilege_escalation"
	PhaseLateral    Phase = "lateral_movement"
	PhaseCollection Phase = "collection"
	PhaseExfil      Phase = "exfiltration"
	PhaseImpact     Phase = "impact"
)

// Status represents a campaign item status
type Status string

const (
	StatusPlanned    Status = "planned"
	StatusActive     Status = "active"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusCancelled  Status = "cancelled"
)

// Objective represents a high-level campaign goal
type Objective struct {
	ID          string
	Description string
	Target      string
	Status      Status
	CreatedAt   time.Time
	CompletedAt *time.Time
	Evidence    []string
}

// Action represents a specific action taken during the campaign
type Action struct {
	ID          string
	CampaignID  string
	OperatorID  string
	Phase       Phase
	Description string
	Target      string
	Tool        string
	Command     string
	Result      string
	Status      Status
	SessionID   string
	StartedAt   time.Time
	CompletedAt *time.Time
	Evidence    []string
	Notes       string
}

// OpCampaign represents an ongoing operation tracked by the phase tracker.
type OpCampaign struct {
	ID         string
	Name       string
	Status     Status
	Objectives []*Objective
	Actions    []*Action
	CreatedAt  time.Time
	CreatedBy  string
	Notes      string
	Config     CampaignConfig
}

// CampaignConfig holds campaign-specific settings
type CampaignConfig struct {
	StealthLevel string // low, medium, high, maximum
	TimeLimit    time.Duration
	AvoidTargets []string
	PreferTech   []string
	KillDate     time.Time
}

// Tracker manages all campaigns and their state
type Tracker struct {
	mu        sync.RWMutex
	campaigns map[string]*OpCampaign
	actions   map[string]*Action
	logger    *zap.Logger
	nextID    int
}

func NewTracker(logger *zap.Logger) *Tracker {
	return &Tracker{
		campaigns: make(map[string]*OpCampaign),
		actions:   make(map[string]*Action),
		logger:    logger.Named("campaign"),
		nextID:    1,
	}
}

// CreateCampaign starts a new campaign
func (t *Tracker) CreateCampaign(name, createdBy string, config CampaignConfig) *OpCampaign {
	t.mu.Lock()
	defer t.mu.Unlock()

	id := fmt.Sprintf("campaign-%d", t.nextID)
	t.nextID++

	c := &OpCampaign{
		ID:        id,
		Name:      name,
		Status:    StatusActive,
		CreatedAt: time.Now(),
		CreatedBy: createdBy,
		Config:    config,
	}

	t.campaigns[id] = c
	t.logger.Info("campaign created",
		zap.String("id", id),
		zap.String("name", name),
		zap.String("operator", createdBy),
	)
	return c
}

// AddObjective adds a goal to a campaign
func (t *Tracker) AddObjective(campaignID, description, target string) (*Objective, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	c, ok := t.campaigns[campaignID]
	if !ok {
		return nil, fmt.Errorf("campaign not found: %s", campaignID)
	}

	obj := &Objective{
		ID:          fmt.Sprintf("obj-%d", len(c.Objectives)+1),
		Description: description,
		Target:      target,
		Status:      StatusPlanned,
		CreatedAt:   time.Now(),
	}

	c.Objectives = append(c.Objectives, obj)
	return obj, nil
}

// LogAction records an operator action
func (t *Tracker) LogAction(campaignID, operatorID string, phase Phase,
	description, target, tool, command string) *Action {
	t.mu.Lock()
	defer t.mu.Unlock()

	id := fmt.Sprintf("action-%d", len(t.actions)+1)
	action := &Action{
		ID:          id,
		CampaignID:  campaignID,
		OperatorID:  operatorID,
		Phase:       phase,
		Description: description,
		Target:      target,
		Tool:        tool,
		Command:     command,
		Status:      StatusActive,
		StartedAt:   time.Now(),
	}

	t.actions[id] = action
	if c, ok := t.campaigns[campaignID]; ok {
		c.Actions = append(c.Actions, action)
	}

	t.logger.Info("action logged",
		zap.String("id", id),
		zap.String("phase", string(phase)),
		zap.String("target", target),
	)
	return action
}

// CompleteAction marks an action as completed with result
func (t *Tracker) CompleteAction(actionID, result string, evidence []string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	action, ok := t.actions[actionID]
	if !ok {
		return fmt.Errorf("action not found: %s", actionID)
	}

	now := time.Now()
	action.Status = StatusCompleted
	action.Result = result
	action.CompletedAt = &now
	action.Evidence = evidence
	return nil
}

// FailAction marks an action as failed
func (t *Tracker) FailAction(actionID, reason string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	action, ok := t.actions[actionID]
	if !ok {
		return fmt.Errorf("action not found: %s", actionID)
	}

	now := time.Now()
	action.Status = StatusFailed
	action.Result = reason
	action.CompletedAt = &now
	return nil
}

// GetCampaign returns a campaign by ID
func (t *Tracker) GetCampaign(id string) (*OpCampaign, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	c, ok := t.campaigns[id]
	if !ok {
		return nil, fmt.Errorf("campaign not found: %s", id)
	}
	return c, nil
}

// ListCampaigns returns all campaigns
func (t *Tracker) ListCampaigns() []*OpCampaign {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []*OpCampaign
	for _, c := range t.campaigns {
		result = append(result, c)
	}
	return result
}

// GetActionsByPhase returns all actions for a given phase
func (t *Tracker) GetActionsByPhase(campaignID string, phase Phase) []*Action {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []*Action
	for _, a := range t.actions {
		if a.CampaignID == campaignID && a.Phase == phase {
			result = append(result, a)
		}
	}
	return result
}

// GetTimeline returns actions sorted by time
func (t *Tracker) GetTimeline(campaignID string) []*Action {
	t.mu.RLock()
	defer t.mu.RUnlock()

	c, ok := t.campaigns[campaignID]
	if !ok {
		return nil
	}
	return c.Actions
}

// GetStats returns campaign statistics
func (t *Tracker) GetStats(campaignID string) map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	c, ok := t.campaigns[campaignID]
	if !ok {
		return nil
	}

	phaseCount := make(map[Phase]int)
	statusCount := make(map[Status]int)
	for _, a := range c.Actions {
		phaseCount[a.Phase]++
		statusCount[a.Status]++
	}

	return map[string]interface{}{
		"campaign_id":      c.ID,
		"name":             c.Name,
		"status":           c.Status,
		"total_actions":    len(c.Actions),
		"total_objectives": len(c.Objectives),
		"actions_by_phase": phaseCount,
		"actions_by_status": statusCount,
		"duration":         time.Since(c.CreatedAt).String(),
	}
}
