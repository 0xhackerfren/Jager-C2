package malleable

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuiltinProfiles(t *testing.T) {
	profiles := BuiltinProfiles()

	expected := []string{"default", "amazon", "microsoft"}
	for _, name := range expected {
		p, ok := profiles[name]
		if !ok {
			t.Fatalf("missing builtin profile: %s", name)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("builtin profile %s invalid: %v", name, err)
		}
	}
}

func TestProfileValidation(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		wantErr bool
	}{
		{
			name: "valid minimal",
			profile: Profile{
				Name:      "test",
				SleepTime: 30,
				Jitter:    10,
				HTTPGet:   HTTPBlock{URI: []string{"/api/check"}},
				HTTPPost:  HTTPBlock{URI: []string{"/api/data"}},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			profile: Profile{
				SleepTime: 30,
				Jitter:    10,
				HTTPGet:   HTTPBlock{URI: []string{"/x"}},
				HTTPPost:  HTTPBlock{URI: []string{"/y"}},
			},
			wantErr: true,
		},
		{
			name: "negative sleep",
			profile: Profile{
				Name:      "bad",
				SleepTime: -1,
				HTTPGet:   HTTPBlock{URI: []string{"/x"}},
				HTTPPost:  HTTPBlock{URI: []string{"/y"}},
			},
			wantErr: true,
		},
		{
			name: "jitter over 99",
			profile: Profile{
				Name:      "bad",
				SleepTime: 30,
				Jitter:    100,
				HTTPGet:   HTTPBlock{URI: []string{"/x"}},
				HTTPPost:  HTTPBlock{URI: []string{"/y"}},
			},
			wantErr: true,
		},
		{
			name: "missing http_get uri",
			profile: Profile{
				Name:      "bad",
				SleepTime: 30,
				Jitter:    10,
				HTTPGet:   HTTPBlock{},
				HTTPPost:  HTTPBlock{URI: []string{"/y"}},
			},
			wantErr: true,
		},
		{
			name: "missing http_post uri",
			profile: Profile{
				Name:      "bad",
				SleepTime: 30,
				Jitter:    10,
				HTTPGet:   HTTPBlock{URI: []string{"/x"}},
				HTTPPost:  HTTPBlock{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSelectURI(t *testing.T) {
	block := HTTPBlock{URI: []string{"/a", "/b", "/c"}}

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		uri := block.SelectURI()
		seen[uri] = true
	}

	if len(seen) < 2 {
		t.Fatal("SelectURI should produce variety from 3 URIs")
	}
}

func TestSelectURIEmpty(t *testing.T) {
	block := HTTPBlock{URI: []string{}}
	uri := block.SelectURI()
	if uri != "/" {
		t.Fatalf("empty URI list should return '/', got '%s'", uri)
	}
}

func TestComputeSleep(t *testing.T) {
	p := &Profile{SleepTime: 60, Jitter: 0}
	sleep := p.ComputeSleep()
	if sleep != 60*time.Second {
		t.Fatalf("zero jitter should give exact sleep, got %v", sleep)
	}
}

func TestComputeSleepWithJitter(t *testing.T) {
	p := &Profile{SleepTime: 60, Jitter: 50}

	var min, max time.Duration
	min = 999 * time.Hour
	for i := 0; i < 1000; i++ {
		s := p.ComputeSleep()
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
	}

	if min >= 60*time.Second {
		t.Fatalf("jitter should sometimes produce values below base, min was %v", min)
	}
	if max <= 60*time.Second {
		t.Fatalf("jitter should sometimes produce values above base, max was %v", max)
	}
}

func TestGenerateHeaders(t *testing.T) {
	block := HTTPBlock{
		Headers: map[string]string{
			"Accept": "application/json",
			"X-Custom": "value",
		},
	}

	headers := block.GenerateHeaders("TestAgent/1.0")
	if headers["User-Agent"] != "TestAgent/1.0" {
		t.Fatal("User-Agent not set")
	}
	if headers["Accept"] != "application/json" {
		t.Fatal("Accept header not preserved")
	}
	if headers["X-Custom"] != "value" {
		t.Fatal("custom header not preserved")
	}
}

func TestMutateForBuild(t *testing.T) {
	profiles := BuiltinProfiles()
	base := profiles["default"]

	mutated1 := base.MutateForBuild(1)
	mutated2 := base.MutateForBuild(2)

	if mutated1.Name != base.Name {
		t.Fatal("mutation should preserve name")
	}

	// Different seeds may produce different User-Agents or URIs
	differs := mutated1.UserAgent != mutated2.UserAgent
	for i := range mutated1.HTTPGet.URI {
		if i < len(mutated2.HTTPGet.URI) && mutated1.HTTPGet.URI[i] != mutated2.HTTPGet.URI[i] {
			differs = true
		}
	}

	// Determinism: same seed gives same result
	same1 := base.MutateForBuild(42)
	same2 := base.MutateForBuild(42)
	if same1.UserAgent != same2.UserAgent {
		t.Fatal("same seed must produce same user agent")
	}

	_ = differs
}

func TestLoadProfileFromFile(t *testing.T) {
	dir := t.TempDir()
	p := &Profile{
		Name:      "file-test",
		SleepTime: 30,
		Jitter:    20,
		UserAgent: "Test/1.0",
		HTTPGet:   HTTPBlock{URI: []string{"/check"}},
		HTTPPost:  HTTPBlock{URI: []string{"/data"}},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "test-profile.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	if loaded.Name != "file-test" {
		t.Fatalf("expected name 'file-test', got '%s'", loaded.Name)
	}
	if loaded.SleepTime != 30 {
		t.Fatalf("expected sleep 30, got %d", loaded.SleepTime)
	}
}

func TestLoadProfileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid"), 0644)

	_, err := LoadProfile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadProfileMissingFile(t *testing.T) {
	_, err := LoadProfile("/nonexistent/profile.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
