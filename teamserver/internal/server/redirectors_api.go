package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/auth"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/redirectors"
)

func (m *ManagementAPI) handleRedirectors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !m.requirePerm(w, r, auth.PermSessionList) {
			return
		}
		if m.srv.redirectors == nil {
			jsonResp(w, map[string]interface{}{"redirectors": []interface{}{}, "count": 0})
			return
		}
		all := m.srv.redirectors.List()
		jsonResp(w, map[string]interface{}{"redirectors": all, "count": len(all)})
	case http.MethodPost:
		if !m.requirePerm(w, r, auth.PermListenerCreate) {
			return
		}
		var red redirectors.Redirector
		if err := json.NewDecoder(r.Body).Decode(&red); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		if m.srv.redirectors == nil {
			jsonErr(w, 500, "redirector manager not initialized")
			return
		}
		if err := m.srv.redirectors.Add(&red); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		m.auditLog(r, "redirector.add", "", red.ID, red.Name)
		jsonResp(w, map[string]interface{}{"success": true, "redirector": red})
	default:
		jsonErr(w, 405, "GET or POST required")
	}
}

func (m *ManagementAPI) handleRedirectorByID(w http.ResponseWriter, r *http.Request) {
	if m.srv.redirectors == nil {
		jsonErr(w, 500, "redirector manager not initialized")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/redirectors/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		jsonErr(w, 400, "redirector id required")
		return
	}
	id := parts[0]

	if len(parts) >= 2 && parts[1] == "burn" {
		m.handleRedirectorBurn(w, r, id)
		return
	}
	if len(parts) >= 2 && parts[1] == "config" {
		m.handleRedirectorConfig(w, r, id)
		return
	}

	if r.Method != http.MethodDelete {
		jsonErr(w, 405, "DELETE required")
		return
	}
	if !m.requirePerm(w, r, auth.PermListenerStop) {
		return
	}
	if err := m.srv.redirectors.Remove(id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	m.auditLog(r, "redirector.remove", "", id, "")
	jsonResp(w, map[string]interface{}{"success": true})
}

func (m *ManagementAPI) handleRedirectorBurn(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	if !m.requirePerm(w, r, auth.PermListenerStop) {
		return
	}
	if err := m.srv.redirectors.MarkBurned(id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	m.auditLog(r, "redirector.burn", "", id, "")
	jsonResp(w, map[string]interface{}{"success": true, "id": id, "status": redirectors.StatusBurned})
}

func (m *ManagementAPI) handleRedirectorConfig(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		jsonErr(w, 405, "GET required")
		return
	}
	if !m.requirePerm(w, r, auth.PermListenerCreate) {
		return
	}
	red, ok := m.srv.redirectors.Get(id)
	if !ok {
		jsonErr(w, 404, "redirector not found")
		return
	}

	listenerPort := red.Port
	if v := r.URL.Query().Get("listener_port"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			listenerPort = n
		}
	}
	uriPath := r.URL.Query().Get("uri_path")
	userAgent := r.URL.Query().Get("user_agent")
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "nginx"
	}

	var config string
	switch format {
	case "apache":
		config = m.srv.redirectors.GenerateApacheConfig(listenerPort, uriPath, userAgent)
	default:
		config = m.srv.redirectors.GenerateNginxConfig(listenerPort, uriPath, userAgent)
	}

	jsonResp(w, map[string]interface{}{
		"id":            id,
		"format":        format,
		"listener_port": listenerPort,
		"config":        config,
	})
}
