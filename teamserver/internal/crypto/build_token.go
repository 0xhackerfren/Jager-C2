package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const DefaultBuildTokenTTL = 30 * 24 * time.Hour

// BuildToken tracks issued build registration tokens with optional expiry.
type BuildToken struct {
	Token     string
	BuildID   string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
}

func (t *BuildToken) IsValid() bool {
	if t == nil {
		return false
	}
	if t.Revoked {
		return false
	}
	if !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt) {
		return false
	}
	return true
}

var (
	buildSecretOnce sync.Once
	buildSecretVal  string
	buildSecretErr  error

	buildTokenRegistry sync.RWMutex
	buildTokens        = make(map[string]*BuildToken) // buildID -> token record
)

func buildSecretPath() string {
	for _, env := range []string{"JAGER_WORKSPACE", "HARNESS_WORKSPACE"} {
		if ws := os.Getenv(env); ws != "" {
			return filepath.Join(ws, "data", "build-secret.txt")
		}
	}
	candidates := []string{
		filepath.Join("data", "build-secret.txt"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return candidates[0]
}

// GetBuildSecret returns the HMAC secret for build token validation.
func GetBuildSecret() string {
	buildSecretOnce.Do(func() {
		if s := os.Getenv("JAGER_BUILD_SECRET"); s != "" {
			buildSecretVal = s
			return
		}

		path := buildSecretPath()
		if data, err := os.ReadFile(path); err == nil {
			s := string(data)
			if len(s) > 0 && s[len(s)-1] == '\n' {
				s = s[:len(s)-1]
			}
			if s != "" {
				buildSecretVal = s
				return
			}
		}

		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			buildSecretErr = fmt.Errorf("generate build secret: %w", err)
			return
		}
		s := hex.EncodeToString(buf)

		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			buildSecretErr = fmt.Errorf("create build secret dir: %w", err)
			return
		}
		if err := os.WriteFile(path, []byte(s+"\n"), 0o600); err != nil {
			buildSecretErr = fmt.Errorf("write build secret: %w", err)
			return
		}
		buildSecretVal = s
	})

	if buildSecretErr != nil {
		panic(buildSecretErr)
	}
	return buildSecretVal
}

// GenerateBuildToken creates an HMAC of the build ID and registers expiry metadata.
func GenerateBuildToken(buildID string) string {
	return IssueBuildToken(buildID, DefaultBuildTokenTTL).Token
}

func computeBuildTokenHMAC(buildID string) string {
	secret := GetBuildSecret()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(buildID))
	return hex.EncodeToString(mac.Sum(nil))
}

// IssueBuildToken registers a build token with the given TTL.
func IssueBuildToken(buildID string, ttl time.Duration) *BuildToken {
	token := computeBuildTokenHMAC(buildID)

	now := time.Now()
	bt := &BuildToken{
		Token:     token,
		BuildID:   buildID,
		CreatedAt: now,
	}
	if ttl != 0 {
		bt.ExpiresAt = now.Add(ttl)
	}

	buildTokenRegistry.Lock()
	buildTokens[buildID] = bt
	buildTokenRegistry.Unlock()
	return bt
}

// RevokeBuildToken marks a build token as unusable.
func RevokeBuildToken(buildID string) {
	buildTokenRegistry.Lock()
	defer buildTokenRegistry.Unlock()
	if bt, ok := buildTokens[buildID]; ok {
		bt.Revoked = true
	}
}

// ValidateBuildToken checks HMAC and registry expiry/revocation state.
func ValidateBuildToken(buildID, token string) bool {
	expected := computeBuildTokenHMAC(buildID)
	if !hmac.Equal([]byte(expected), []byte(token)) {
		return false
	}

	buildTokenRegistry.RLock()
	bt, ok := buildTokens[buildID]
	buildTokenRegistry.RUnlock()
	if ok {
		return bt.IsValid()
	}
	return true
}
