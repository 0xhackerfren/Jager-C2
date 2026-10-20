package campaign

import (
	"testing"

	"go.uber.org/zap"
)

func newTestTracker() *Tracker {
	return NewTracker(zap.NewNop())
}

func TestCreateCampaign(t *testing.T) {
	tracker := newTestTracker()

	c := tracker.CreateCampaign("Test Op", "operator-1", CampaignConfig{
		StealthLevel: "medium",
	})

	if c.ID == "" {
		t.Fatal("campaign should have an ID")
	}
	if c.Name != "Test Op" {
		t.Fatalf("expected name 'Test Op', got '%s'", c.Name)
	}
	if c.Status != StatusActive {
		t.Fatalf("new campaign should be active, got %s", c.Status)
	}
	if c.CreatedBy != "operator-1" {
		t.Fatalf("expected operator 'operator-1', got '%s'", c.CreatedBy)
	}
}

func TestCreateMultipleCampaigns(t *testing.T) {
	tracker := newTestTracker()

	c1 := tracker.CreateCampaign("Op Alpha", "op-1", CampaignConfig{})
	c2 := tracker.CreateCampaign("Op Bravo", "op-2", CampaignConfig{})

	if c1.ID == c2.ID {
		t.Fatal("campaign IDs must be unique")
	}

	all := tracker.ListCampaigns()
	if len(all) != 2 {
		t.Fatalf("expected 2 campaigns, got %d", len(all))
	}
}

func TestAddObjective(t *testing.T) {
	tracker := newTestTracker()
	c := tracker.CreateCampaign("Test", "op-1", CampaignConfig{})

	obj, err := tracker.AddObjective(c.ID, "Compromise DC", "10.0.0.1")
	if err != nil {
		t.Fatalf("AddObjective: %v", err)
	}

	if obj.ID == "" {
		t.Fatal("objective should have an ID")
	}
	if obj.Status != StatusPlanned {
		t.Fatalf("new objective should be planned, got %s", obj.Status)
	}
	if obj.Target != "10.0.0.1" {
		t.Fatalf("expected target '10.0.0.1', got '%s'", obj.Target)
	}

	if len(c.Objectives) != 1 {
		t.Fatalf("campaign should have 1 objective, got %d", len(c.Objectives))
	}
}

func TestAddObjectiveInvalidCampaign(t *testing.T) {
	tracker := newTestTracker()

	_, err := tracker.AddObjective("nonexistent", "Goal", "target")
	if err == nil {
		t.Fatal("expected error for nonexistent campaign")
	}
}

func TestLogAndCompleteAction(t *testing.T) {
	tracker := newTestTracker()
	c := tracker.CreateCampaign("Test", "op-1", CampaignConfig{})

	action := tracker.LogAction(c.ID, "op-1", PhaseRecon, "Port scan", "10.0.0.1", "nmap", "nmap -sV 10.0.0.1")

	if action.ID == "" {
		t.Fatal("action should have an ID")
	}
	if action.Status != StatusActive {
		t.Fatalf("new action should be active, got %s", action.Status)
	}
	if action.Phase != PhaseRecon {
		t.Fatalf("expected phase recon, got %s", action.Phase)
	}

	err := tracker.CompleteAction(action.ID, "Found 5 open ports", []string{"evidence/nmap.txt"})
	if err != nil {
		t.Fatalf("CompleteAction: %v", err)
	}

	if action.Status != StatusCompleted {
		t.Fatalf("action should be completed, got %s", action.Status)
	}
	if action.Result != "Found 5 open ports" {
		t.Fatalf("unexpected result: %s", action.Result)
	}
	if action.CompletedAt == nil {
		t.Fatal("CompletedAt should be set")
	}
}

func TestFailAction(t *testing.T) {
	tracker := newTestTracker()
	c := tracker.CreateCampaign("Test", "op-1", CampaignConfig{})
	action := tracker.LogAction(c.ID, "op-1", PhaseExecution, "Exploit", "10.0.0.5", "msf", "exploit/...")

	err := tracker.FailAction(action.ID, "target not vulnerable")
	if err != nil {
		t.Fatalf("FailAction: %v", err)
	}

	if action.Status != StatusFailed {
		t.Fatalf("action should be failed, got %s", action.Status)
	}
}

func TestCompleteActionInvalid(t *testing.T) {
	tracker := newTestTracker()
	err := tracker.CompleteAction("nonexistent", "result", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent action")
	}
}

func TestFailActionInvalid(t *testing.T) {
	tracker := newTestTracker()
	err := tracker.FailAction("nonexistent", "reason")
	if err == nil {
		t.Fatal("expected error for nonexistent action")
	}
}

func TestGetCampaign(t *testing.T) {
	tracker := newTestTracker()
	c := tracker.CreateCampaign("Lookup Test", "op-1", CampaignConfig{})

	found, err := tracker.GetCampaign(c.ID)
	if err != nil {
		t.Fatalf("GetCampaign: %v", err)
	}
	if found.Name != "Lookup Test" {
		t.Fatalf("expected 'Lookup Test', got '%s'", found.Name)
	}
}

func TestGetCampaignNotFound(t *testing.T) {
	tracker := newTestTracker()
	_, err := tracker.GetCampaign("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent campaign")
	}
}

func TestGetActionsByPhase(t *testing.T) {
	tracker := newTestTracker()
	c := tracker.CreateCampaign("Phase Test", "op-1", CampaignConfig{})

	tracker.LogAction(c.ID, "op-1", PhaseRecon, "scan", "10.0.0.1", "nmap", "nmap ...")
	tracker.LogAction(c.ID, "op-1", PhaseRecon, "dns", "10.0.0.1", "dig", "dig ...")
	tracker.LogAction(c.ID, "op-1", PhaseLateral, "psexec", "10.0.0.5", "se", "se ...")

	recon := tracker.GetActionsByPhase(c.ID, PhaseRecon)
	if len(recon) != 2 {
		t.Fatalf("expected 2 recon actions, got %d", len(recon))
	}

	lateral := tracker.GetActionsByPhase(c.ID, PhaseLateral)
	if len(lateral) != 1 {
		t.Fatalf("expected 1 lateral action, got %d", len(lateral))
	}
}

func TestGetTimeline(t *testing.T) {
	tracker := newTestTracker()
	c := tracker.CreateCampaign("Timeline Test", "op-1", CampaignConfig{})

	tracker.LogAction(c.ID, "op-1", PhaseRecon, "first", "10.0.0.1", "", "")
	tracker.LogAction(c.ID, "op-1", PhaseExecution, "second", "10.0.0.1", "", "")

	timeline := tracker.GetTimeline(c.ID)
	if len(timeline) != 2 {
		t.Fatalf("expected 2 timeline entries, got %d", len(timeline))
	}
}

func TestGetTimelineNotFound(t *testing.T) {
	tracker := newTestTracker()
	timeline := tracker.GetTimeline("nonexistent")
	if timeline != nil {
		t.Fatal("expected nil for nonexistent campaign")
	}
}

func TestGetStats(t *testing.T) {
	tracker := newTestTracker()
	c := tracker.CreateCampaign("Stats Test", "op-1", CampaignConfig{})

	tracker.LogAction(c.ID, "op-1", PhaseRecon, "scan", "10.0.0.1", "", "")
	a := tracker.LogAction(c.ID, "op-1", PhaseExecution, "exploit", "10.0.0.5", "", "")
	tracker.CompleteAction(a.ID, "got shell", nil)

	stats := tracker.GetStats(c.ID)
	if stats == nil {
		t.Fatal("expected stats")
	}
	if stats["total_actions"].(int) != 2 {
		t.Fatalf("expected 2 total actions, got %v", stats["total_actions"])
	}
}

func TestGetStatsNotFound(t *testing.T) {
	tracker := newTestTracker()
	stats := tracker.GetStats("nonexistent")
	if stats != nil {
		t.Fatal("expected nil for nonexistent campaign")
	}
}
