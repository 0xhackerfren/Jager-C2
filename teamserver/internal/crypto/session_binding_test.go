package crypto

import "testing"

func TestSessionBindingHMAC(t *testing.T) {
	sessionID := "abcd-1234"
	hmacVal := ComputeSessionHMAC(sessionID)
	if !ValidateSessionBinding(sessionID, hmacVal) {
		t.Fatal("expected valid session binding")
	}
	if ValidateSessionBinding(sessionID, "wrong-header") {
		t.Fatal("wrong header should not validate")
	}
}

func TestSessionBindingLegacyID(t *testing.T) {
	sessionID := "legacy-session-id"
	if !ValidateSessionBinding(sessionID, sessionID) {
		t.Fatal("legacy raw session id header should still validate")
	}
}
