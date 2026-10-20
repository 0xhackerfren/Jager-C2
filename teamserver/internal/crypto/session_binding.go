package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

const sessionBindingPrefix = "session-bind:"

// ComputeSessionHMAC returns the HMAC binding token for a session ID.
// Implants should send this value in the X-Implant-Id header after registration.
func ComputeSessionHMAC(sessionID string) string {
	secret := GetBuildSecret()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionBindingPrefix))
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateSessionBinding checks that the transport header binds to the session ID.
func ValidateSessionBinding(sessionID, implantHeader string) bool {
	if sessionID == "" || implantHeader == "" {
		return false
	}
	expected := ComputeSessionHMAC(sessionID)
	if hmac.Equal([]byte(implantHeader), []byte(expected)) {
		return true
	}
	// Legacy implants may still send the raw session ID in the header.
	return subtle.ConstantTimeCompare([]byte(implantHeader), []byte(sessionID)) == 1
}
