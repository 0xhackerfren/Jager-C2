package listeners

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/tasks"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
)

type stubBuildStore struct{}

func (stubBuildStore) GetStagePayload(string) ([]byte, error) { return nil, nil }

func TestDecryptSessionBodyRejectsPlaintextWhenCryptoActive(t *testing.T) {
	sessionMgr := sessions.NewManager(zap.NewNop())
	taskQ := tasks.NewQueue(zap.NewNop(), sessionMgr)
	l := &HTTPSListener{sessions: sessionMgr, tasks: taskQ, logger: zap.NewNop()}

	serverSC, _, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, clientPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client GenerateKeyPair: %v", err)
	}
	if err := serverSC.DeriveSessionKey(clientPub); err != nil {
		t.Fatalf("DeriveSessionKey: %v", err)
	}

	sessionID := "secure-session"
	sessionMgr.RegisterSession(&pb.ImplantRegistration{
		ImplantId: sessionID,
		Hostname:  "host",
		Username:  "user",
	}, serverSC)

	plain := []byte(`{"id":"secure-session"}`)
	_, _, err = l.decryptSessionBodyStrict(sessionID, plain)
	if err == nil {
		t.Fatal("expected plaintext rejection when session crypto is active")
	}
}

func TestCheckinRequiresImplantHeader(t *testing.T) {
	sessionMgr := sessions.NewManager(zap.NewNop())
	taskQ := tasks.NewQueue(zap.NewNop(), sessionMgr)
	l, err := NewHTTPSListener(&pb.ListenerConfig{BindHost: "127.0.0.1", BindPort: 0}, sessionMgr, taskQ, stubBuildStore{}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewHTTPSListener: %v", err)
	}

	sessionID := "checkin-session"
	sessionMgr.RegisterSession(&pb.ImplantRegistration{
		ImplantId: sessionID,
		Hostname:  "host",
		Username:  "user",
	}, nil)

	body, _ := json.Marshal(map[string]string{"id": sessionID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/checkin", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	l.handleCheckin(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without X-Implant-Id, got %d", rec.Code)
	}
}

func TestIsRegistrationRequest(t *testing.T) {
	regBody, _ := json.Marshal(map[string]string{
		"build_id": "build-1",
		"hostname": "host-1",
	})
	if !isRegistrationRequest(regBody) {
		t.Fatal("expected registration body to be detected")
	}

	checkinBody, _ := json.Marshal(map[string]string{"id": "sess-1"})
	if isRegistrationRequest(checkinBody) {
		t.Fatal("checkin body should not look like registration")
	}
}
