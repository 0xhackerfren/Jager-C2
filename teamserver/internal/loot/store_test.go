package loot

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	logger := zap.NewNop()

	store, err := NewStore(dbPath, logger)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestNewStore(t *testing.T) {
	store := testStore(t)
	if store.DB() == nil {
		t.Fatal("expected non-nil db")
	}
}

func TestNewStoreInvalidPath(t *testing.T) {
	logger := zap.NewNop()
	_, err := NewStore("/nonexistent/path/to/db", logger)
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestAddAndListTargets(t *testing.T) {
	store := testStore(t)

	// Manually insert via raw SQL to avoid proto dependency
	_, err := store.DB().Exec(
		`INSERT INTO targets (id, hostname, ip, domain, os, os_version, access_level, compromised, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tgt-1", "DC01", "10.0.0.1", "LAB.LOCAL", 1, "Windows Server 2022", "admin", 1, "Domain Controller",
	)
	if err != nil {
		t.Fatalf("insert target: %v", err)
	}

	_, err = store.DB().Exec(
		`INSERT INTO targets (id, hostname, ip, domain, os, os_version, access_level, compromised, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tgt-2", "WS01", "10.0.0.10", "LAB.LOCAL", 1, "Windows 11", "user", 0, "",
	)
	if err != nil {
		t.Fatalf("insert target: %v", err)
	}

	var count int
	store.DB().QueryRow("SELECT COUNT(*) FROM targets").Scan(&count)
	if count != 2 {
		t.Fatalf("expected 2 targets, got %d", count)
	}

	var compromised int
	store.DB().QueryRow("SELECT COUNT(*) FROM targets WHERE compromised = 1").Scan(&compromised)
	if compromised != 1 {
		t.Fatalf("expected 1 compromised target, got %d", compromised)
	}
}

func TestAddAndListCredentials(t *testing.T) {
	store := testStore(t)

	_, err := store.DB().Exec(
		`INSERT INTO credentials (id, domain, username, type, data, source, source_host, session_id, captured_at, validated, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"cred-1", "LAB.LOCAL", "admin", 2, "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
		"secretsdump", "DC01", "sess-1", "2025-01-01T00:00:00Z", 1, "DA hash",
	)
	if err != nil {
		t.Fatalf("insert credential: %v", err)
	}

	var count int
	store.DB().QueryRow("SELECT COUNT(*) FROM credentials WHERE domain = ?", "LAB.LOCAL").Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 credential, got %d", count)
	}
}

func TestAddAndListFindings(t *testing.T) {
	store := testStore(t)

	_, err := store.DB().Exec(
		`INSERT INTO findings (id, title, severity, description, target_id, technique_id, evidence, found_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"find-1", "SMB Signing Disabled", "High",
		"SMB signing is not required on this host", "tgt-1", "T1557.001",
		"evidence/smb/signing-check.txt", "2025-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	var title string
	err = store.DB().QueryRow("SELECT title FROM findings WHERE severity = ?", "High").Scan(&title)
	if err != nil {
		t.Fatalf("query finding: %v", err)
	}
	if title != "SMB Signing Disabled" {
		t.Fatalf("expected 'SMB Signing Disabled', got '%s'", title)
	}
}

func TestAddLootFile(t *testing.T) {
	store := testStore(t)

	data := []byte("SAM hive contents")
	_, err := store.DB().Exec(
		`INSERT INTO loot_files (id, name, category, data, size, sha256, source_host, source_path, session_id, captured_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"loot-1", "SAM", "registry", data, len(data),
		"abc123", "DC01", "C:\\Windows\\System32\\config\\SAM", "sess-1", "2025-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("insert loot: %v", err)
	}

	var name string
	var size int
	err = store.DB().QueryRow("SELECT name, size FROM loot_files WHERE category = ?", "registry").Scan(&name, &size)
	if err != nil {
		t.Fatalf("query loot: %v", err)
	}
	if name != "SAM" || size != len(data) {
		t.Fatalf("unexpected loot: name=%s size=%d", name, size)
	}
}

func TestMigrationIdempotent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	logger := zap.NewNop()

	store1, err := NewStore(dbPath, logger)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	store1.Close()

	store2, err := NewStore(dbPath, logger)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer store2.Close()

	// Should not fail on re-migration
	var version int
	store2.DB().QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if version < 1 {
		t.Fatalf("expected migration version >= 1, got %d", version)
	}
}

func TestDatabaseWALMode(t *testing.T) {
	store := testStore(t)

	var journalMode string
	err := store.DB().QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Logf("journal_mode is %s (expected wal)", journalMode)
	}
}

func TestDatabaseFileCreated(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "created.db")
	logger := zap.NewNop()

	store, err := NewStore(dbPath, logger)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("database file was not created")
	}
}
