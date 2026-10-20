package loot

import (
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type Migration struct {
	Version int
	Name    string
	SQL     string
}

var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial_schema",
		SQL: `
		CREATE TABLE IF NOT EXISTS credentials (
			id TEXT PRIMARY KEY,
			domain TEXT,
			username TEXT,
			type INTEGER,
			data TEXT,
			source TEXT,
			source_host TEXT,
			session_id TEXT,
			captured_at TEXT,
			validated INTEGER DEFAULT 0,
			notes TEXT
		);
		CREATE TABLE IF NOT EXISTS targets (
			id TEXT PRIMARY KEY,
			hostname TEXT,
			ip TEXT,
			domain TEXT,
			os INTEGER,
			os_version TEXT,
			services TEXT,
			access_level TEXT DEFAULT 'none',
			compromised INTEGER DEFAULT 0,
			session_ids TEXT,
			first_seen TEXT,
			last_accessed TEXT,
			notes TEXT
		);
		CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			title TEXT,
			severity TEXT,
			description TEXT,
			target_id TEXT,
			technique_id TEXT,
			evidence TEXT,
			found_at TEXT
		);
		CREATE TABLE IF NOT EXISTS pivots (
			id TEXT PRIMARY KEY,
			source_session_id TEXT,
			target_host TEXT,
			transport INTEGER,
			pipe_name TEXT,
			port INTEGER,
			active INTEGER DEFAULT 1
		);
		CREATE TABLE IF NOT EXISTS loot_files (
			id TEXT PRIMARY KEY,
			name TEXT,
			category TEXT,
			data BLOB,
			size INTEGER,
			sha256 TEXT,
			source_host TEXT,
			source_path TEXT,
			session_id TEXT,
			captured_at TEXT
		);
		CREATE TABLE IF NOT EXISTS access_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT,
			target_id TEXT,
			method TEXT,
			status TEXT,
			timestamp TEXT
		);
		CREATE TABLE IF NOT EXISTS technique_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			technique_id TEXT,
			technique_name TEXT,
			tactic TEXT,
			session_id TEXT,
			target_id TEXT,
			tool_name TEXT,
			success INTEGER,
			timestamp TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_creds_domain ON credentials(domain);
		CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip);
		CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
		CREATE INDEX IF NOT EXISTS idx_access_session ON access_log(session_id);
		CREATE INDEX IF NOT EXISTS idx_technique_tactic ON technique_log(tactic);
		`,
	},
	{
		Version: 2,
		Name:    "add_campaigns_operators",
		SQL: `
		CREATE TABLE IF NOT EXISTS operators (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			cert_fingerprint TEXT,
			role TEXT DEFAULT 'operator',
			created_at TEXT,
			last_login TEXT,
			active INTEGER DEFAULT 1
		);
		CREATE TABLE IF NOT EXISTS campaigns (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			created_by TEXT,
			created_at TEXT,
			started_at TEXT,
			ended_at TEXT,
			status TEXT DEFAULT 'planning'
		);
		CREATE TABLE IF NOT EXISTS campaign_sessions (
			campaign_id TEXT,
			session_id TEXT,
			added_at TEXT,
			PRIMARY KEY (campaign_id, session_id)
		);
		ALTER TABLE access_log ADD COLUMN operator_id TEXT DEFAULT '';
		ALTER TABLE technique_log ADD COLUMN operator_id TEXT DEFAULT '';
		`,
	},
	{
		Version: 3,
		Name:    "add_build_records",
		SQL: `
		CREATE TABLE IF NOT EXISTS builds (
			id TEXT PRIMARY KEY,
			type TEXT,
			format TEXT,
			profile TEXT,
			save_path TEXT,
			file_hash TEXT,
			file_size INTEGER,
			config_json TEXT,
			created_at TEXT,
			created_by TEXT
		);
		CREATE TABLE IF NOT EXISTS session_builds (
			session_id TEXT,
			build_id TEXT,
			PRIMARY KEY (session_id, build_id)
		);
		`,
	},
	{
		Version: 4,
		Name:    "add_event_stream",
		SQL: `
		CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			session_id TEXT,
			operator_id TEXT,
			data TEXT,
			created_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
		CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
		CREATE INDEX IF NOT EXISTS idx_events_time ON events(created_at);
		`,
	},
	{
		Version: 5,
		Name:    "add_session_persistence",
		SQL: `
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			hostname TEXT,
			username TEXT,
			domain TEXT,
			os INTEGER DEFAULT 0,
			arch TEXT,
			pid INTEGER DEFAULT 0,
			elevated INTEGER DEFAULT 0,
			internal_ip TEXT,
			external_ip TEXT,
			transport TEXT,
			build_id TEXT,
			alive INTEGER DEFAULT 1,
			note TEXT,
			is_beacon INTEGER DEFAULT 0,
			interval_seconds INTEGER DEFAULT 0,
			jitter_percent INTEGER DEFAULT 0,
			registered_at TEXT NOT NULL,
			last_checkin TEXT NOT NULL,
			killed_at TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_alive ON sessions(alive);
		CREATE INDEX IF NOT EXISTS idx_sessions_hostname ON sessions(hostname);

		CREATE TABLE IF NOT EXISTS task_queue (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			type INTEGER NOT NULL,
			state INTEGER NOT NULL DEFAULT 0,
			request_data BLOB,
			response_data BLOB,
			error TEXT,
			exit_code INTEGER DEFAULT 0,
			created_at TEXT NOT NULL,
			sent_at TEXT,
			completed_at TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_taskq_session ON task_queue(session_id);
		CREATE INDEX IF NOT EXISTS idx_taskq_state ON task_queue(state);
		`,
	},
	{
		Version: 6,
		Name:    "add_session_reconnect_history",
		SQL: `
		CREATE TABLE IF NOT EXISTS session_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			previous_state TEXT,
			new_state TEXT,
			reconnect_from TEXT,
			metadata TEXT,
			timestamp TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_session_history_id ON session_history(session_id);
		CREATE INDEX IF NOT EXISTS idx_session_history_type ON session_history(event_type);

		ALTER TABLE sessions ADD COLUMN reconnect_count INTEGER DEFAULT 0;
		ALTER TABLE sessions ADD COLUMN original_registered_at TEXT;
		ALTER TABLE sessions ADD COLUMN previous_session_id TEXT;
		`,
	},
	{
		Version: 7,
		Name:    "add_session_labels",
		SQL:     `ALTER TABLE sessions ADD COLUMN labels TEXT DEFAULT '[]';`,
	},
	{
		Version: 8,
		Name:    "add_build_platform",
		SQL:     `ALTER TABLE builds ADD COLUMN platform TEXT DEFAULT '';`,
	},
}

func runMigrations(db *sql.DB, logger *zap.Logger) error {
	// Create migrations tracking table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT,
			applied_at TEXT
		)
	`)
	if err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	currentVersion := 0
	row := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
	row.Scan(&currentVersion)

	for _, m := range migrations {
		if m.Version <= currentVersion {
			continue
		}

		logger.Info("applying migration",
			zap.Int("version", m.Version),
			zap.String("name", m.Name),
		)

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", m.Version, err)
		}

		if _, err := tx.Exec(m.SQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d (%s): %w", m.Version, m.Name, err)
		}

		if _, err := tx.Exec(
			"INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
			m.Version, m.Name, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.Version, err)
		}

		logger.Info("migration applied", zap.Int("version", m.Version))
	}

	return nil
}
