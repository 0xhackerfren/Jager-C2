package sessions

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func anyToInt32(v any) int32 {
	switch x := v.(type) {
	case int32:
		return x
	case int:
		return int32(x)
	case float64:
		return int32(x)
	case pb.OS:
		return int32(x)
	default:
		return 0
	}
}

func anyToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// SetDB enables session persistence to SQLite.
func (m *Manager) SetDB(db *sql.DB) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db = db
}

// PersistSession writes or updates a session record in SQLite.
func (m *Manager) PersistSession(sess *pb.Session) {
	if m.db == nil || sess == nil {
		return
	}

	reg := sess.Registration
	hostname, username, domain, arch, buildID := "", "", "", "", ""
	var osVal int32
	var pid int32
	var elevated bool
	var internalIP string

	if reg != nil {
		hostname = reg.Hostname
		username = reg.Username
		domain = reg.Domain
		osVal = anyToInt32(reg.Os)
		arch = anyToString(reg.Arch)
		pid = reg.Pid
		elevated = reg.Elevated
		internalIP = reg.InternalIp
		buildID = reg.BuildId
	}

	now := time.Now().UTC().Format(time.RFC3339)
	lastCheckin := now
	if sess.LastCheckin != nil {
		lastCheckin = sess.LastCheckin.AsTime().Format(time.RFC3339)
	}

	labelsJSON := "[]"
	if len(sess.Labels) > 0 {
		if lb, err := json.Marshal(sess.Labels); err == nil {
			labelsJSON = string(lb)
		}
	}

	_, err := m.db.Exec(`
		INSERT INTO sessions (id, hostname, username, domain, os, arch, pid, elevated,
			internal_ip, transport, build_id, alive, note, labels, is_beacon,
			interval_seconds, jitter_percent, registered_at, last_checkin)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			alive = excluded.alive,
			last_checkin = excluded.last_checkin,
			note = excluded.note,
			labels = excluded.labels
	`,
		sess.Id, hostname, username, domain, osVal, arch, pid, elevated,
		internalIP, sess.ActiveTransport.String(), buildID,
		sess.Alive, sess.Note, labelsJSON, now, lastCheckin,
	)
	if err != nil {
		m.logger.Error("failed to persist session", zap.String("id", sess.Id), zap.Error(err))
	}
}

// PersistBeacon writes or updates a beacon record in SQLite.
func (m *Manager) PersistBeacon(beacon *pb.Beacon) {
	if m.db == nil || beacon == nil {
		return
	}

	reg := beacon.Registration
	hostname, username, domain, arch, buildID := "", "", "", "", ""
	var osVal int32
	var pid int32
	var elevated bool
	var internalIP string

	if reg != nil {
		hostname = reg.Hostname
		username = reg.Username
		domain = reg.Domain
		osVal = anyToInt32(reg.Os)
		arch = anyToString(reg.Arch)
		pid = reg.Pid
		elevated = reg.Elevated
		internalIP = reg.InternalIp
		buildID = reg.BuildId
	}

	now := time.Now().UTC().Format(time.RFC3339)
	lastCheckin := now
	if beacon.LastCheckin != nil {
		lastCheckin = beacon.LastCheckin.AsTime().Format(time.RFC3339)
	}

	_, err := m.db.Exec(`
		INSERT INTO sessions (id, hostname, username, domain, os, arch, pid, elevated,
			internal_ip, transport, build_id, alive, note, is_beacon,
			interval_seconds, jitter_percent, registered_at, last_checkin)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			alive = excluded.alive,
			last_checkin = excluded.last_checkin,
			interval_seconds = excluded.interval_seconds,
			jitter_percent = excluded.jitter_percent,
			note = excluded.note
	`,
		beacon.Id, hostname, username, domain, osVal, arch, pid, elevated,
		internalIP, beacon.ActiveTransport.String(), buildID,
		beacon.Alive, beacon.Note, beacon.IntervalSeconds, beacon.JitterPercent,
		now, lastCheckin,
	)
	if err != nil {
		m.logger.Error("failed to persist beacon", zap.String("id", beacon.Id), zap.Error(err))
	}
}

// LoadPersistedSessions restores sessions from SQLite on startup.
// Sessions that were alive are marked as RECONNECTING (alive=false until
// the implant re-registers). Crypto state is not persisted (implant re-does ECDH).
func (m *Manager) LoadPersistedSessions() (loaded int, err error) {
	if m.db == nil {
		return 0, nil
	}

	rows, err := m.db.Query(`
		SELECT id, hostname, username, domain, os, arch, pid, elevated,
			internal_ip, transport, build_id, alive, note, is_beacon,
			interval_seconds, jitter_percent, registered_at, last_checkin
		FROM sessions
	`)
	if err != nil {
		return 0, fmt.Errorf("query persisted sessions: %w", err)
	}
	defer rows.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	for rows.Next() {
		var (
			id, hostname, username, domain, arch, internalIP string
			transport, buildID, note, registeredAt, lastCheckinStr string
			osVal, pid                                             int32
			elevated, alive, isBeacon                              bool
			intervalSec, jitterPct                                 uint32
		)

		err = rows.Scan(&id, &hostname, &username, &domain, &osVal, &arch,
			&pid, &elevated, &internalIP, &transport, &buildID,
			&alive, &note, &isBeacon, &intervalSec, &jitterPct,
			&registeredAt, &lastCheckinStr)
		if err != nil {
			m.logger.Error("scan persisted session", zap.Error(err))
			continue
		}

		lastCheckin, _ := time.Parse(time.RFC3339, lastCheckinStr)

		reg := &pb.ImplantRegistration{
			ImplantId:  id,
			Hostname:   hostname,
			Username:   username,
			Domain:     domain,
			Os:         osVal,
			Pid:        pid,
			Elevated:   elevated,
			InternalIp: internalIP,
			BuildId:    buildID,
		}

		if isBeacon {
			staleTimeout := time.Duration(intervalSec*3) * time.Second
			beaconAlive := alive && now.Sub(lastCheckin) < staleTimeout

			beacon := &pb.Beacon{
				Id:              id,
				Registration:    reg,
				LastCheckin:     timestamppb.New(lastCheckin),
				NextCheckin:     timestamppb.New(lastCheckin.Add(time.Duration(intervalSec) * time.Second)),
				IntervalSeconds: intervalSec,
				JitterPercent:   jitterPct,
				Alive:           beaconAlive,
				ActiveTransport: parseTransport(transport),
				RemoteAddr:      internalIP,
				Note:            note,
			}
			m.beacons[id] = beacon
		} else {
			sessionAlive := alive && now.Sub(lastCheckin) < 5*time.Minute

			sess := &Session{
				Data: &pb.Session{
					Id:              id,
					Registration:    reg,
					LastCheckin:     timestamppb.New(lastCheckin),
					Alive:           sessionAlive,
					ActiveTransport: parseTransport(transport),
					RemoteAddr:      internalIP,
					Note:            note,
				},
				Crypto: nil,
			}
			m.sessions[id] = sess
		}
		loaded++
	}

	if loaded > 0 {
		m.logger.Info("restored persisted sessions", zap.Int("count", loaded))
	}
	return loaded, rows.Err()
}

// MarkKilled persists kill state to SQLite.
func (m *Manager) MarkKilled(id string) {
	if m.db == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := m.db.Exec(`UPDATE sessions SET alive = 0, killed_at = ? WHERE id = ?`, now, id)
	if err != nil {
		m.logger.Error("failed to persist kill", zap.String("id", id), zap.Error(err))
	}
}

// UpdateCheckin persists checkin timestamp to SQLite.
func (m *Manager) UpdateCheckin(id string) {
	if m.db == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = m.db.Exec(`UPDATE sessions SET last_checkin = ?, alive = 1 WHERE id = ?`, now, id)
}

func parseTransport(s string) pb.Transport {
	switch s {
	case "TRANSPORT_HTTPS":
		return pb.Transport_TRANSPORT_HTTPS
	case "TRANSPORT_DNS":
		return pb.Transport_TRANSPORT_DNS
	case "TRANSPORT_TCP":
		return pb.Transport_TRANSPORT_TCP
	case "TRANSPORT_SMB":
		return pb.Transport_TRANSPORT_SMB
	default:
		return pb.Transport_TRANSPORT_HTTPS
	}
}

// ExportSessionsJSON returns a JSON snapshot of all sessions for debugging.
func (m *Manager) ExportSessionsJSON() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	type exportEntry struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
		User     string `json:"user"`
		Alive    bool   `json:"alive"`
		IsBeacon bool   `json:"is_beacon"`
	}

	var entries []exportEntry
	for _, s := range m.sessions {
		if s.Data == nil {
			continue
		}
		hostname := ""
		user := ""
		if s.Data.Registration != nil {
			hostname = s.Data.Registration.Hostname
			user = s.Data.Registration.Username
		}
		entries = append(entries, exportEntry{
			ID:       s.Data.Id,
			Hostname: hostname,
			User:     user,
			Alive:    s.Data.Alive,
			IsBeacon: false,
		})
	}
	for _, b := range m.beacons {
		hostname := ""
		user := ""
		if b.Registration != nil {
			hostname = b.Registration.Hostname
			user = b.Registration.Username
		}
		entries = append(entries, exportEntry{
			ID:       b.Id,
			Hostname: hostname,
			User:     user,
			Alive:    b.Alive,
			IsBeacon: true,
		})
	}
	return json.Marshal(entries)
}

// RecordReconnect logs a session reconnect event to the history table.
// Called when an implant re-registers with a known session ID.
func (m *Manager) RecordReconnect(sessionID, previousState string) {
	if m.db == nil {
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	_, err := m.db.Exec(`
		INSERT INTO session_history (session_id, event_type, previous_state, new_state, timestamp)
		VALUES (?, 'reconnect', ?, 'alive', ?)
	`, sessionID, previousState, now)
	if err != nil {
		m.logger.Error("failed to record reconnect", zap.String("id", sessionID), zap.Error(err))
		return
	}

	_, _ = m.db.Exec(`
		UPDATE sessions SET reconnect_count = COALESCE(reconnect_count, 0) + 1
		WHERE id = ?
	`, sessionID)
}

// GetSessionHistory returns the reconnect history for a session.
func (m *Manager) GetSessionHistory(sessionID string) ([]map[string]string, error) {
	if m.db == nil {
		return nil, fmt.Errorf("no database configured")
	}

	rows, err := m.db.Query(`
		SELECT event_type, previous_state, new_state, reconnect_from, metadata, timestamp
		FROM session_history
		WHERE session_id = ?
		ORDER BY timestamp ASC
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []map[string]string
	for rows.Next() {
		var eventType, prevState, newState, from, meta, ts sql.NullString
		if err := rows.Scan(&eventType, &prevState, &newState, &from, &meta, &ts); err != nil {
			continue
		}
		entry := map[string]string{
			"event_type":     eventType.String,
			"previous_state": prevState.String,
			"new_state":      newState.String,
			"reconnect_from": from.String,
			"metadata":       meta.String,
			"timestamp":      ts.String,
		}
		history = append(history, entry)
	}
	return history, nil
}

// GetReconnectCount returns how many times a session has reconnected.
func (m *Manager) GetReconnectCount(sessionID string) int {
	if m.db == nil {
		return 0
	}
	var count int
	_ = m.db.QueryRow(`SELECT COALESCE(reconnect_count, 0) FROM sessions WHERE id = ?`, sessionID).Scan(&count)
	return count
}
