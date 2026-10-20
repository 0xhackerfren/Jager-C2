package builds

import (
	"testing"

	"go.uber.org/zap"
)

func TestStoreRegisterAndGet(t *testing.T) {
	s, err := NewStore(t.TempDir(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register("test-001", "implant", "exe", "default", "test.exe"); err != nil {
		t.Fatal("register failed:", err)
	}
	rec, err := s.Get("test-001")
	if err != nil {
		t.Fatal("build not found after register")
	}
	if rec.ID != "test-001" {
		t.Errorf("expected test-001, got %s", rec.ID)
	}
}

func TestStorePathTraversal(t *testing.T) {
	s, err := NewStore(t.TempDir(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register("evil", "implant", "exe", "default", "../../../etc/passwd"); err == nil {
		t.Error("path traversal build should be rejected")
	}
}

func TestValidateEvasionRequest(t *testing.T) {
	cases := []struct {
		name    string
		req     BuildRequest
		wantErr bool
	}{
		{"empty ok", BuildRequest{}, false},
		{"valid inject", BuildRequest{InjectMethod: "threadless"}, false},
		{"valid sleep", BuildRequest{SleepTechnique: "zilean"}, false},
		{"valid amsi", BuildRequest{AmsiBypassMethod: "hwbp"}, false},
		{"invalid inject", BuildRequest{InjectMethod: "bogus"}, true},
		{"invalid sleep", BuildRequest{SleepTechnique: "bogus"}, true},
		{"invalid amsi", BuildRequest{AmsiBypassMethod: "bogus"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEvasionRequest(tc.req)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
