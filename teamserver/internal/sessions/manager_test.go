package sessions

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
)

func testRegistration(id string) *pb.ImplantRegistration {
	return &pb.ImplantRegistration{
		ImplantId:  id,
		Hostname:   "testhost",
		Username:   "testuser",
		Transport:  pb.Transport_TRANSPORT_HTTPS,
		InternalIp: "10.0.0.1",
	}
}

func TestRegisterAndGet(t *testing.T) {
	mgr := NewManager(zap.NewNop())
	reg := testRegistration("sess-1")

	mgr.RegisterSession(reg, nil)

	sess, err := mgr.GetSession("sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.Id != "sess-1" {
		t.Fatalf("expected sess-1, got %s", sess.Id)
	}
	if !sess.Alive {
		t.Fatal("expected session to be alive")
	}
}

func TestConcurrentRegistration(t *testing.T) {
	mgr := NewManager(zap.NewNop())
	const n = 100

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("sess-%d", i)
			mgr.RegisterSession(testRegistration(id), nil)
		}()
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("sess-%d", i)
		if !mgr.SessionExists(id) {
			t.Fatalf("session %s not registered", id)
		}
	}
}

func TestKillSession(t *testing.T) {
	mgr := NewManager(zap.NewNop())
	reg := testRegistration("sess-kill")
	mgr.RegisterSession(reg, nil)

	if err := mgr.Kill("sess-kill", false); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	sess, err := mgr.GetSession("sess-kill")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.Alive {
		t.Fatal("expected session to be dead after kill")
	}
}

func TestCheckinUpdatesTime(t *testing.T) {
	mgr := NewManager(zap.NewNop())
	reg := testRegistration("sess-checkin")
	mgr.RegisterSession(reg, nil)

	before, err := mgr.GetSession("sess-checkin")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	first := before.LastCheckin.AsTime()

	time.Sleep(5 * time.Millisecond)

	if err := mgr.Checkin("sess-checkin"); err != nil {
		t.Fatalf("Checkin: %v", err)
	}

	after, err := mgr.GetSession("sess-checkin")
	if err != nil {
		t.Fatalf("GetSession after checkin: %v", err)
	}
	second := after.LastCheckin.AsTime()

	if !second.After(first) {
		t.Fatalf("checkin did not update LastCheckin: before=%v after=%v", first, second)
	}
}

func TestReregisterInvalidatesCrypto(t *testing.T) {
	mgr := NewManager(zap.NewNop())
	reg := testRegistration("sess-rereg")

	serverSC, serverPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, clientPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client GenerateKeyPair: %v", err)
	}
	if err := serverSC.DeriveSessionKey(clientPub); err != nil {
		t.Fatalf("server DeriveSessionKey: %v", err)
	}

	mgr.RegisterSession(reg, serverSC)
	if !serverSC.Ready() {
		t.Fatal("expected first registration crypto ready")
	}

	newSC, _, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair new: %v", err)
	}
	if err := newSC.DeriveSessionKey(clientPub); err != nil {
		t.Fatalf("new DeriveSessionKey: %v", err)
	}
	_ = serverPub

	mgr.RegisterSession(reg, newSC)

	if serverSC.Ready() {
		t.Fatal("expected old crypto invalidated after re-registration")
	}
	if !newSC.Ready() {
		t.Fatal("expected new crypto ready after re-registration")
	}

	stored := mgr.GetSessionCrypto("sess-rereg")
	if stored != newSC {
		t.Fatal("expected session manager to reference new crypto")
	}
}
