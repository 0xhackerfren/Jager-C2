package listeners

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
)

// isRegistrationRequest detects first-contact registration payloads.
func isRegistrationRequest(body []byte) bool {
	if len(body) == 0 || !json.Valid(body) {
		return false
	}
	var probe struct {
		BuildID  string `json:"build_id"`
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return probe.BuildID != "" && probe.Hostname != ""
}

func validateSessionBinding(sessionID, implantHeader string) bool {
	return crypto.ValidateSessionBinding(sessionID, implantHeader)
}

func computeSessionHMAC(sessionID string) string {
	return crypto.ComputeSessionHMAC(sessionID)
}

func (l *HTTPSListener) resolveSessionFromHeader(header string) string {
	if header == "" {
		return ""
	}
	if l.sessions.SessionExists(header) {
		return header
	}
	for _, sess := range l.sessions.GetSessions(false) {
		if validateSessionBinding(sess.Id, header) {
			return sess.Id
		}
	}
	return header
}

func (l *HTTPSListener) enforceSessionBinding(sessionID, implantHeader string) bool {
	if sessionID == "" || implantHeader == "" {
		return false
	}
	return validateSessionBinding(sessionID, implantHeader)
}

// decryptSessionBody fails closed when a session has active wire crypto.
func (l *HTTPSListener) decryptSessionBodyStrict(sessionID string, body []byte) ([]byte, string, error) {
	if len(body) == 0 {
		return body, sessionID, nil
	}

	sc := l.sessions.GetSessionCrypto(sessionID)
	if sc == nil {
		if !json.Valid(body) {
			return nil, sessionID, errEncryptedBodyRequired
		}
		return body, sessionID, nil
	}

	if !sc.Ready() {
		return nil, sessionID, errEncryptedBodyRequired
	}

	plain, resolvedID, err := l.decryptEncryptedBody(sessionID, body, sc)
	if err != nil {
		return nil, sessionID, err
	}
	return plain, resolvedID, nil
}

func decodeWireBody(body []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return body, nil
	}
	return raw, nil
}

func (l *HTTPSListener) decryptEncryptedBody(sessionID string, body []byte, sc *crypto.SessionCrypto) ([]byte, string, error) {
	raw, err := decodeWireBody(body)
	if err != nil {
		return nil, sessionID, err
	}

	if sc != nil && sc.Ready() {
		plain, err := sc.Decrypt(raw)
		if err != nil {
			idPrefix := sessionID
			if len(idPrefix) > 8 {
				idPrefix = idPrefix[:8]
			}
			return nil, sessionID, fmt.Errorf("decryption failed for session %s: %w", idPrefix, err)
		}
		return plain, sessionID, nil
	}

	if sessionID != "" {
		if sc := l.sessions.GetSessionCrypto(sessionID); sc != nil && sc.Ready() {
			plain, err := sc.Decrypt(raw)
			return plain, sessionID, err
		}
	}

	id, plain, err := l.sessions.DecryptBySessionPrefix(raw)
	if err != nil {
		return nil, sessionID, err
	}
	return plain, id, nil
}
