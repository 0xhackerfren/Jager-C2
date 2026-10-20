package loot

import (
	"database/sql"
	"fmt"
	"strings"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/listeners"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

type Store struct {
	db     *sql.DB
	logger *zap.Logger
}

func NewStore(dbPath string, logger *zap.Logger) (*Store, error) {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return nil, fmt.Errorf("database path is required")
	}
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	s := &Store{db: db, logger: logger}
	if err := runMigrations(db, logger); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}
	return s, nil
}

func (s *Store) Close() {
	s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) migrate() error {
	schema := `
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
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) AddCredential(cred *pb.Credential) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO credentials (id, domain, username, type, data, source, source_host, session_id, captured_at, validated, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cred.Id, cred.Domain, cred.Username, int(cred.Type), cred.Data,
		cred.Source, cred.SourceHost, cred.SessionId,
		cred.CapturedAt.AsTime().Format("2006-01-02T15:04:05Z"),
		cred.Validated, cred.Notes,
	)
	return err
}

func (s *Store) ListCredentials(domain string, credType pb.CredType) ([]*pb.Credential, error) {
	query := "SELECT id, domain, username, type, data, source, source_host, session_id, validated, notes FROM credentials WHERE 1=1"
	var args []interface{}

	if domain != "" {
		query += " AND domain = ?"
		args = append(args, domain)
	}
	if credType != pb.CredType_CRED_UNKNOWN {
		query += " AND type = ?"
		args = append(args, int(credType))
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*pb.Credential
	for rows.Next() {
		var c pb.Credential
		var ct int
		err := rows.Scan(&c.Id, &c.Domain, &c.Username, &ct, &c.Data, &c.Source, &c.SourceHost, &c.SessionId, &c.Validated, &c.Notes)
		if err != nil {
			continue
		}
		c.Type = pb.CredType(ct)
		creds = append(creds, &c)
	}
	return creds, nil
}

func (s *Store) AddTarget(target *pb.Target) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO targets (id, hostname, ip, domain, os, os_version, access_level, compromised, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		target.Id, target.Hostname, target.Ip, target.Domain,
		int(target.Os), target.OsVersion, target.AccessLevel,
		target.Compromised, target.Notes,
	)
	return err
}

func (s *Store) ListTargets(compromisedOnly bool) ([]*pb.Target, error) {
	query := "SELECT id, hostname, ip, domain, os, os_version, access_level, compromised, notes FROM targets"
	if compromisedOnly {
		query += " WHERE compromised = 1"
	}

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*pb.Target
	for rows.Next() {
		var t pb.Target
		var osInt int
		err := rows.Scan(&t.Id, &t.Hostname, &t.Ip, &t.Domain, &osInt, &t.OsVersion, &t.AccessLevel, &t.Compromised, &t.Notes)
		if err != nil {
			continue
		}
		t.Os = pb.OS(osInt)
		targets = append(targets, &t)
	}
	return targets, nil
}

func (s *Store) AddFinding(f *pb.Finding) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO findings (id, title, severity, description, target_id, technique_id, evidence, found_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.Id, f.Title, f.Severity, f.Description, f.TargetId, f.TechniqueId, f.Evidence,
		f.FoundAt.AsTime().Format("2006-01-02T15:04:05Z"),
	)
	return err
}

func (s *Store) ListFindings(severity string) ([]*pb.Finding, error) {
	query := "SELECT id, title, severity, description, target_id, technique_id, evidence FROM findings"
	var args []interface{}
	if severity != "" {
		query += " WHERE severity = ?"
		args = append(args, severity)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*pb.Finding
	for rows.Next() {
		var f pb.Finding
		err := rows.Scan(&f.Id, &f.Title, &f.Severity, &f.Description, &f.TargetId, &f.TechniqueId, &f.Evidence)
		if err != nil {
			continue
		}
		findings = append(findings, &f)
	}
	return findings, nil
}

func (s *Store) AddPivot(p *pb.Pivot) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO pivots (id, source_session_id, target_host, transport, pipe_name, port, active)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.Id, p.SourceSessionId, p.TargetHost, int(p.Transport), p.PipeName, p.Port, p.Active,
	)
	return err
}

func (s *Store) ListPivots(activeOnly bool) ([]*pb.Pivot, error) {
	query := "SELECT id, source_session_id, target_host, transport, pipe_name, port, active FROM pivots"
	if activeOnly {
		query += " WHERE active = 1"
	}

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pivots []*pb.Pivot
	for rows.Next() {
		var p pb.Pivot
		var transport int
		err := rows.Scan(&p.Id, &p.SourceSessionId, &p.TargetHost, &transport, &p.PipeName, &p.Port, &p.Active)
		if err != nil {
			continue
		}
		p.Transport = pb.Transport(transport)
		pivots = append(pivots, &p)
	}
	return pivots, nil
}

func (s *Store) StoreLoot(l *pb.LootFile) error {
	_, err := s.db.Exec(
		`INSERT INTO loot_files (id, name, category, data, size, sha256, source_host, source_path, session_id, captured_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.Id, l.Name, l.Category, l.Data, l.Size, l.Sha256,
		l.SourceHost, l.SourcePath, l.SessionId,
		l.CapturedAt.AsTime().Format("2006-01-02T15:04:05Z"),
	)
	return err
}

func (s *Store) ListLoot(category string) ([]*pb.LootFile, error) {
	query := "SELECT id, name, category, size, sha256, source_host, source_path, session_id FROM loot_files"
	var args []interface{}
	if category != "" {
		query += " WHERE category = ?"
		args = append(args, category)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*pb.LootFile
	for rows.Next() {
		var l pb.LootFile
		err := rows.Scan(&l.Id, &l.Name, &l.Category, &l.Size, &l.Sha256, &l.SourceHost, &l.SourcePath, &l.SessionId)
		if err != nil {
			continue
		}
		items = append(items, &l)
	}
	return items, nil
}

func (s *Store) GetLootByID(id string) (*pb.LootFile, error) {
	row := s.db.QueryRow(
		"SELECT id, name, category, data, size, sha256, source_host, source_path, session_id FROM loot_files WHERE id = ?", id)
	var l pb.LootFile
	err := row.Scan(&l.Id, &l.Name, &l.Category, &l.Data, &l.Size, &l.Sha256, &l.SourceHost, &l.SourcePath, &l.SessionId)
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) GetLootStats() (map[string]int, error) {
	rows, err := s.db.Query("SELECT category, COUNT(*) FROM loot_files GROUP BY category")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stats := make(map[string]int)
	for rows.Next() {
		var cat string
		var count int
		if rows.Scan(&cat, &count) == nil {
			stats[cat] = count
		}
	}
	return stats, nil
}

func (s *Store) LogAccess(entry *pb.AccessLog) error {
	_, err := s.db.Exec(
		`INSERT INTO access_log (session_id, target_id, method, status, timestamp)
		 VALUES (?, ?, ?, ?, ?)`,
		entry.SessionId, entry.TargetId, entry.Method, entry.Status,
		entry.Timestamp.AsTime().Format("2006-01-02T15:04:05Z"),
	)
	return err
}

func (s *Store) LogTechnique(entry *pb.TechniqueLog) error {
	_, err := s.db.Exec(
		`INSERT INTO technique_log (technique_id, technique_name, tactic, session_id, target_id, tool_name, success, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.TechniqueId, entry.TechniqueName, entry.Tactic, entry.SessionId,
		entry.TargetId, entry.ToolName, entry.Success,
		entry.Timestamp.AsTime().Format("2006-01-02T15:04:05Z"),
	)
	return err
}

func (s *Store) GetSummary(sessMgr *sessions.Manager, lisMgr *listeners.Manager) (*pb.EngagementSummary, error) {
	activeSess, activeBeacons := sessMgr.GetActiveCount()
	allSess := len(sessMgr.GetSessions(false))
	allBeacons := len(sessMgr.GetBeacons(false))

	var totalTargets, compromised, totalCreds, totalFindings, techCount int

	s.db.QueryRow("SELECT COUNT(*) FROM targets").Scan(&totalTargets)
	s.db.QueryRow("SELECT COUNT(*) FROM targets WHERE compromised = 1").Scan(&compromised)
	s.db.QueryRow("SELECT COUNT(*) FROM credentials").Scan(&totalCreds)
	s.db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&totalFindings)
	s.db.QueryRow("SELECT COUNT(DISTINCT technique_id) FROM technique_log").Scan(&techCount)

	return &pb.EngagementSummary{
		TotalSessions:       uint32(allSess),
		ActiveSessions:      uint32(activeSess),
		TotalBeacons:        uint32(allBeacons),
		ActiveBeacons:       uint32(activeBeacons),
		TotalTargets:        uint32(totalTargets),
		CompromisedTargets:  uint32(compromised),
		TotalCredentials:    uint32(totalCreds),
		TotalFindings:       uint32(totalFindings),
		TechniquesUsed:      uint32(techCount),
		ActiveListeners:     listenerIDs(lisMgr),
	}, nil
}

func listenerIDs(mgr *listeners.Manager) []string {
	configs := mgr.List()
	ids := make([]string, len(configs))
	for i, c := range configs {
		ids[i] = c.Id
	}
	return ids
}
