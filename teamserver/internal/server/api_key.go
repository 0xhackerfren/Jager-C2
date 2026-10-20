package server

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// EnsureMgmtAPIKey loads or generates the management REST/gRPC API key.
func EnsureMgmtAPIKey(workspace, dbPath string, logger *zap.Logger) string {
	if key := strings.TrimSpace(os.Getenv("JAGER_MGMT_API_KEY")); key != "" {
		return key
	}

	keyFile := apiKeyFilePath(workspace, dbPath)
	if data, err := os.ReadFile(keyFile); err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			_ = os.Setenv("JAGER_MGMT_API_KEY", key)
			return key
		}
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		if logger != nil {
			logger.Fatal("generate api key", zap.Error(err))
		}
		panic(err)
	}
	key := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
		if logger != nil {
			logger.Fatal("create api key dir", zap.Error(err))
		}
		panic(err)
	}
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		if logger != nil {
			logger.Fatal("write api key", zap.Error(err))
		}
		panic(err)
	}
	_ = os.Setenv("JAGER_MGMT_API_KEY", key)
	if logger != nil {
		logger.Info("Generated new management API key", zap.String("path", keyFile))
	}
	return key
}

func apiKeyFilePath(workspace, dbPath string) string {
	if workspace != "" {
		return filepath.Join(workspace, "data", "api-key.txt")
	}
	if dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "api-key.txt")
	}
	return filepath.Join("data", "api-key.txt")
}
