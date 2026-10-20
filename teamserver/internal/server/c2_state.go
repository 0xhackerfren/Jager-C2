package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var c2StateMu sync.Mutex

// writeC2State appends deterministic state for agent session resume.
func writeC2State(workspace, event string, payload map[string]interface{}) {
	if workspace == "" {
		return
	}
	c2StateMu.Lock()
	defer c2StateMu.Unlock()

	logDir := filepath.Join(workspace, "engagements", "dante", "logs")
	_ = os.MkdirAll(logDir, 0o755)
	statePath := filepath.Join(logDir, "c2-state.json")

	entry := map[string]interface{}{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"event":   event,
		"payload": payload,
	}

	var doc map[string]interface{}
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, &doc)
	}
	if doc == nil {
		doc = map[string]interface{}{"events": []interface{}{}}
	}
	events, _ := doc["events"].([]interface{})
	events = append(events, entry)
	if len(events) > 500 {
		events = events[len(events)-500:]
	}
	doc["events"] = events
	doc["updated_at"] = entry["ts"]

	out, _ := json.MarshalIndent(doc, "", "  ")
	_ = os.WriteFile(statePath, out, 0o644)
}
