package crypto

import (
	"testing"
	"time"
)

func TestBuildTokenRoundTrip(t *testing.T) {
	token := GenerateBuildToken("test-build-123")
	if !ValidateBuildToken("test-build-123", token) {
		t.Fatal("valid token rejected")
	}
}

func TestBuildTokenWrongID(t *testing.T) {
	token := GenerateBuildToken("build-A")
	if ValidateBuildToken("build-B", token) {
		t.Fatal("wrong build ID accepted")
	}
}

func TestBuildTokenExpiry(t *testing.T) {
	buildID := "expiring-build"
	bt := IssueBuildToken(buildID, -time.Hour)
	if bt.IsValid() {
		t.Fatal("expired token should be invalid")
	}
	if ValidateBuildToken(buildID, bt.Token) {
		t.Fatal("expired token should fail validation")
	}
}

func TestBuildTokenRevocation(t *testing.T) {
	buildID := "revoked-build"
	token := IssueBuildToken(buildID, time.Hour).Token
	RevokeBuildToken(buildID)
	if ValidateBuildToken(buildID, token) {
		t.Fatal("revoked token should fail validation")
	}
}
