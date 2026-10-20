package builds

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/events"
	"go.uber.org/zap"
)

type BuildRecord struct {
	ID            string
	Type          string // "implant" or "stager"
	Format        string // "exe", "dll", "shellcode"
	Profile       string
	SavePath      string
	CreatedAt     time.Time
	Size          int64
	ConfigJSON    string
	Seed          string
	ProfileHash   string
	IntegrityHash string
	Platform      string // windows, linux
}

type BuildMeta struct {
	Seed        string
	ProfileHash string
	Platform    string
	ConfigJSON  string
}

type Store struct {
	mu       sync.RWMutex
	builds   map[string]*BuildRecord
	stages   map[string][]byte // buildID -> encrypted stage-1 payload
	buildDir string
	logger   *zap.Logger
	db       *sql.DB
	events   *events.Bus
}

func NewStore(buildDir string, logger *zap.Logger) (*Store, error) {
	if err := os.MkdirAll(buildDir, 0750); err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	return &Store{
		builds:   make(map[string]*BuildRecord),
		stages:   make(map[string][]byte),
		buildDir: buildDir,
		logger:   logger,
	}, nil
}

func (s *Store) SetDB(db *sql.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = db
}

func (s *Store) SetEventBus(bus *events.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = bus
}

func (s *Store) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, type, format, profile, save_path, COALESCE(file_hash, ''), file_size, COALESCE(config_json, ''), created_at, COALESCE(platform, '') FROM builds`)
	if err != nil {
		return err
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var rec BuildRecord
		var created, fileHash string
		if err := rows.Scan(&rec.ID, &rec.Type, &rec.Format, &rec.Profile, &rec.SavePath, &fileHash, &rec.Size, &rec.ConfigJSON, &created, &rec.Platform); err != nil {
			return err
		}
		rec.IntegrityHash = fileHash
		if rec.Platform == "" {
			rec.Platform = inferPlatform(rec.Format, rec.Type)
		}
		if rec.ProfileHash == "" && rec.ConfigJSON != "" {
			var cfg map[string]interface{}
			if json.Unmarshal([]byte(rec.ConfigJSON), &cfg) == nil {
				if v, ok := cfg["profile_fingerprint"].(string); ok {
					rec.ProfileHash = v
				}
				if v, ok := cfg["build_nonce"].(string); ok {
					rec.Seed = v
				}
			}
		}
		if t, err := time.Parse(time.RFC3339, created); err == nil {
			rec.CreatedAt = t
		}
		s.builds[rec.ID] = &rec
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.restoreRoutes()
	return s.loadStagesFromDisk()
}

// restoreRoutes re-registers malleable routes for all builds that have config
// overlay data. Must be called with s.mu held.
func (s *Store) restoreRoutes() {
	if s.logger != nil {
		s.logger.Info("restoreRoutes: scanning builds", zap.Int("count", len(s.builds)))
	}
	for _, rec := range s.builds {
		if rec.ConfigJSON == "" {
			if s.logger != nil {
				s.logger.Debug("restoreRoutes: skip (no config)", zap.String("build", rec.ID))
			}
			continue
		}
		var overlay struct {
			CheckinPath  string `json:"checkin_path"`
			RegisterPath string `json:"register_path"`
			ResultPath   string `json:"result_path"`
			StagePath    string `json:"stage1_path"`
			TunnelPath   string `json:"tunnel_path"`
		}
		if err := json.Unmarshal([]byte(rec.ConfigJSON), &overlay); err != nil {
			if s.logger != nil {
				s.logger.Warn("restoreRoutes: unmarshal failed", zap.String("build", rec.ID), zap.Error(err))
			}
			continue
		}
		if overlay.CheckinPath == "" && overlay.RegisterPath == "" {
			if s.logger != nil {
				s.logger.Debug("restoreRoutes: skip (no paths)", zap.String("build", rec.ID))
			}
			continue
		}
		malleablePath := filepath.Join(s.buildDir, fmt.Sprintf("malleable-%s.json", rec.ID))
		if _, err := os.Stat(malleablePath); os.IsNotExist(err) {
			malleablePath = filepath.Join(s.buildDir, "profile.json")
		}
		_ = LoadAndRegisterMalleableProfile(
			rec.ID, malleablePath,
			overlay.CheckinPath, overlay.RegisterPath,
			overlay.ResultPath, overlay.StagePath, overlay.TunnelPath,
		)
		if s.logger != nil {
			s.logger.Info("restored malleable routes for build",
				zap.String("build_id", rec.ID),
				zap.String("register", overlay.RegisterPath),
				zap.String("checkin", overlay.CheckinPath),
			)
		}
	}
}

func (s *Store) stageFilePath(buildID string) string {
	clean := filepath.Base(buildID)
	if clean == "." || clean == ".." || clean == "" {
		return ""
	}
	return filepath.Join(s.buildDir, "stages", clean+".enc")
}

func (s *Store) loadStagesFromDisk() error {
	stageDir := filepath.Join(s.buildDir, "stages")
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".enc" {
			continue
		}
		buildID := ent.Name()[:len(ent.Name())-len(".enc")]
		data, err := os.ReadFile(filepath.Join(stageDir, ent.Name()))
		if err != nil {
			s.logger.Warn("load stage file failed", zap.String("build_id", buildID), zap.Error(err))
			continue
		}
		s.stages[buildID] = data
		s.logger.Info("stage payload loaded from disk",
			zap.String("build_id", buildID),
			zap.Int("size", len(data)),
		)
	}
	return nil
}

func (s *Store) Register(id, buildType, format, profile, savePath string) error {
	return s.RegisterWithMeta(id, buildType, format, profile, savePath, BuildMeta{})
}

func (s *Store) RegisterWithMeta(id, buildType, format, profile, savePath string, meta BuildMeta) error {
	if strings.Contains(savePath, "..") {
		err := fmt.Errorf("invalid save path (traversal): %s", savePath)
		s.logger.Warn("build registration rejected",
			zap.String("id", id),
			zap.String("save_path", savePath),
			zap.Error(err),
		)
		return err
	}
	if filepath.IsAbs(savePath) {
		rel, err := filepath.Rel(s.buildDir, savePath)
		if err == nil && !strings.HasPrefix(rel, "..") {
			savePath = rel
		}
	}
	s.mu.Lock()
	rec := s.makeRecord(id, buildType, format, profile, savePath, meta)
	s.builds[id] = rec
	db := s.db
	bus := s.events
	s.mu.Unlock()

	s.logger.Info("build registered",
		zap.String("id", id),
		zap.String("type", buildType),
		zap.String("format", format),
		zap.String("platform", rec.Platform),
		zap.String("integrity_hash", rec.IntegrityHash),
		zap.Int64("size", rec.Size),
	)
	s.persist(db, rec)
	crypto.IssueBuildToken(id, crypto.DefaultBuildTokenTTL)
	if bus != nil {
		bus.Publish(events.Event{
			Type: events.EventBuildComplete,
			Data: map[string]interface{}{
				"build_id":       id,
				"type":           buildType,
				"format":         format,
				"platform":       rec.Platform,
				"profile":        profile,
				"profile_hash":   rec.ProfileHash,
				"seed":           rec.Seed,
				"integrity_hash": rec.IntegrityHash,
				"size":           rec.Size,
			},
		})
	}
	return nil
}

func (s *Store) UpdateConfig(id string, configJSON []byte) {
	s.mu.Lock()
	rec, ok := s.builds[id]
	if ok {
		rec.ConfigJSON = string(configJSON)
	}
	db := s.db
	s.mu.Unlock()
	if ok && db != nil {
		_, _ = db.Exec(`UPDATE builds SET config_json = ? WHERE id = ?`, string(configJSON), id)
	}
}

func (s *Store) makeRecord(id, buildType, format, profile, savePath string, meta BuildMeta) *BuildRecord {
	var size int64
	var integrityHash string
	path := savePath
	if path != "" && !filepath.IsAbs(path) {
		path = filepath.Join(s.buildDir, path)
	}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			size = int64(len(data))
			sum := sha256.Sum256(data)
			integrityHash = hex.EncodeToString(sum[:])
		} else if st, err := os.Stat(path); err == nil {
			size = st.Size()
		}
	}

	platform := meta.Platform
	if platform == "" {
		platform = inferPlatform(format, buildType)
	}

	configJSON := meta.ConfigJSON
	if configJSON == "" && (meta.Seed != "" || meta.ProfileHash != "") {
		b, _ := json.Marshal(map[string]string{
			"build_nonce":          meta.Seed,
			"profile_fingerprint": meta.ProfileHash,
		})
		configJSON = string(b)
	}

	return &BuildRecord{
		ID:            id,
		Type:          buildType,
		Format:        format,
		Profile:       profile,
		SavePath:      savePath,
		CreatedAt:     time.Now(),
		Size:          size,
		ConfigJSON:    configJSON,
		Seed:          meta.Seed,
		ProfileHash:   meta.ProfileHash,
		IntegrityHash: integrityHash,
		Platform:      platform,
	}
}

func inferPlatform(format, buildType string) string {
	switch format {
	case "elf", "so":
		return "linux"
	default:
		return "windows"
	}
}

func (s *Store) persist(db *sql.DB, rec *BuildRecord) {
	if db == nil {
		return
	}
	_, err := db.Exec(`INSERT OR REPLACE INTO builds
		(id, type, format, profile, save_path, file_hash, file_size, config_json, created_at, created_by, platform)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Type, rec.Format, rec.Profile, rec.SavePath, rec.IntegrityHash, rec.Size, rec.ConfigJSON,
		rec.CreatedAt.UTC().Format(time.RFC3339), "teamserver", rec.Platform,
	)
	if err != nil {
		s.logger.Warn("persist build failed", zap.String("id", rec.ID), zap.Error(err))
	}
}

func (s *Store) StoreStagePayload(buildID string, payload []byte) {
	s.mu.Lock()
	s.stages[buildID] = payload
	s.mu.Unlock()

	stagePath := s.stageFilePath(buildID)
	if stagePath == "" {
		s.logger.Warn("stage payload rejected: invalid build_id", zap.String("build_id", buildID))
		return
	}
	if err := os.MkdirAll(filepath.Dir(stagePath), 0750); err != nil {
		s.logger.Warn("create stage dir failed", zap.Error(err))
	} else if err := os.WriteFile(stagePath, payload, 0640); err != nil {
		s.logger.Warn("persist stage file failed", zap.String("build_id", buildID), zap.Error(err))
	}

	s.logger.Info("stage payload stored",
		zap.String("build_id", buildID),
		zap.Int("size", len(payload)),
	)
}

func (s *Store) GetStagePayload(buildID string) ([]byte, error) {
	s.mu.RLock()
	payload, ok := s.stages[buildID]
	s.mu.RUnlock()
	if ok {
		return payload, nil
	}

	stagePath := s.stageFilePath(buildID)
	if stagePath == "" {
		return nil, fmt.Errorf("stage payload not found: %s", buildID)
	}
	data, err := os.ReadFile(stagePath)
	if err != nil {
		return nil, fmt.Errorf("stage payload not found: %s", buildID)
	}
	s.mu.Lock()
	s.stages[buildID] = data
	s.mu.Unlock()
	return data, nil
}

func (s *Store) Get(id string) (*BuildRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.builds[id]
	if !ok {
		return nil, fmt.Errorf("build not found: %s", id)
	}
	return rec, nil
}

func (s *Store) List() []*BuildRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*BuildRecord
	for _, r := range s.builds {
		result = append(result, r)
	}
	return result
}

func (s *Store) GetBuildData(id string) ([]byte, error) {
	rec, err := s.Get(id)
	if err != nil {
		return nil, err
	}

	path := rec.SavePath
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.buildDir, path)
	}

	cleanPath := filepath.Clean(path)
	buildRoot := filepath.Clean(s.buildDir)
	rel, err := filepath.Rel(buildRoot, cleanPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("path traversal detected: %s", path)
	}

	return os.ReadFile(cleanPath)
}

func (s *Store) BuildDir() string {
	return s.buildDir
}
