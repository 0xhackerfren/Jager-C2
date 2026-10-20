package redirectors

import (
	"strings"
	"testing"
)

func TestAddListRemove(t *testing.T) {
	m := NewManager(nil)
	r := &Redirector{
		Name:       "edge-1",
		ExternalIP: "203.0.113.10",
		InternalIP: "10.0.0.5",
		Port:       443,
		Protocol:   "https",
	}
	if err := m.Add(r); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if r.ID == "" {
		t.Fatal("expected generated ID")
	}

	all := m.List()
	if len(all) != 1 {
		t.Fatalf("expected 1 redirector, got %d", len(all))
	}

	got, ok := m.Get(r.ID)
	if !ok || got.Name != "edge-1" {
		t.Fatal("Get failed")
	}

	if err := m.Remove(r.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := m.Get(r.ID); ok {
		t.Fatal("redirector should be removed")
	}
}

func TestMarkBurned(t *testing.T) {
	m := NewManager(nil)
	r := &Redirector{Name: "burn-test", InternalIP: "127.0.0.1", Port: 8443}
	if err := m.Add(r); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkBurned(r.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(r.ID)
	if got.Status != StatusBurned {
		t.Fatalf("expected burned, got %s", got.Status)
	}
}

func TestGenerateNginxConfig(t *testing.T) {
	m := NewManager(nil)
	cfg := m.GenerateNginxConfig(8443, "/api/v1/checkin,/api/v1/register",
		"TestAgent/1.0")
	if !strings.Contains(cfg, "upstream jager_teamserver") {
		t.Fatal("missing upstream block")
	}
	if !strings.Contains(cfg, "location = /api/v1/checkin") {
		t.Fatal("missing checkin location")
	}
	if !strings.Contains(cfg, "TestAgent/1.0") {
		t.Fatal("missing user-agent match")
	}
	if !strings.Contains(cfg, "return 404") {
		t.Fatal("missing decoy 404")
	}
	if !strings.Contains(cfg, "ssl_certificate") {
		t.Fatal("missing TLS config")
	}
}

func TestGenerateApacheConfig(t *testing.T) {
	m := NewManager(nil)
	cfg := m.GenerateApacheConfig(443, "/api/v1/stage", "Mozilla/5.0")
	if !strings.Contains(cfg, "RewriteEngine On") {
		t.Fatal("missing rewrite engine")
	}
	if !strings.Contains(cfg, "ProxyPreserveHost On") {
		t.Fatal("missing proxy headers section")
	}
	if !strings.Contains(cfg, "SSLEngine on") {
		t.Fatal("missing SSL config")
	}
}
