package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/auth"
	"go.uber.org/zap"
)

func testKeyStore(t *testing.T, key string) *APIKeyStore {
	t.Helper()
	store := NewAPIKeyStore(zap.NewNop())
	store.Add(OperatorKey{
		Operator: "default",
		Key:      key,
		Role:     "admin",
	})
	return store
}

func TestAuthMiddlewareFailsClosedWhenKeyNotConfigured(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/mgmt/sessions", nil)
	rec := httptest.NewRecorder()
	authMiddleware(&Server{}, next).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when API key not configured, got %d", rec.Code)
	}
	if called {
		t.Fatal("handler should not run when API key is not configured")
	}
}

func TestAuthMiddlewareRejectsMissingKey(t *testing.T) {
	store := testKeyStore(t, "test-secret-key")
	srv, _ := New(&Config{}, zap.NewNop(), store)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/mgmt/sessions", nil)
	rec := httptest.NewRecorder()
	authMiddleware(srv, next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if called {
		t.Fatal("handler should not run without api key")
	}
}

func TestAuthMiddlewareAllowsValidKey(t *testing.T) {
	store := testKeyStore(t, "test-secret-key")
	srv, _ := New(&Config{}, zap.NewNop(), store)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/mgmt/sessions", nil)
	req.Header.Set("X-Jager-C2-Api-Key", "test-secret-key")
	rec := httptest.NewRecorder()
	authMiddleware(srv, next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Fatal("handler should run with valid api key")
	}
}

func TestAuthMiddlewareDerivesOperatorFromKey(t *testing.T) {
	store := testKeyStore(t, "test-secret-key")
	srv, _ := New(&Config{}, zap.NewNop(), store)

	var gotName string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if op, ok := r.Context().Value(operatorCtxKey).(*auth.Operator); ok && op != nil {
			gotName = op.Name
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/mgmt/sessions", nil)
	req.Header.Set("X-Jager-C2-Api-Key", "test-secret-key")
	rec := httptest.NewRecorder()
	authMiddleware(srv, next).ServeHTTP(rec, req)

	if gotName != "default" {
		t.Fatalf("expected operator default from api key, got %q", gotName)
	}
}

func TestAuthMiddlewareIgnoresOperatorHeader(t *testing.T) {
	store := NewAPIKeyStore(zap.NewNop())
	store.Add(OperatorKey{Operator: "real-op", Key: "test-secret-key", Role: "admin"})
	srv, _ := New(&Config{}, zap.NewNop(), store)

	var gotName string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if op, ok := r.Context().Value(operatorCtxKey).(*auth.Operator); ok && op != nil {
			gotName = op.Name
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/mgmt/sessions", nil)
	req.Header.Set("X-Jager-C2-Api-Key", "test-secret-key")
	req.Header.Set("X-Jager-C2-Operator", "spoofed-op")
	rec := httptest.NewRecorder()
	authMiddleware(srv, next).ServeHTTP(rec, req)

	if gotName != "real-op" {
		t.Fatalf("expected operator from api key, got %q", gotName)
	}
}

func TestAuthMiddlewarePingOpen(t *testing.T) {
	store := testKeyStore(t, "test-secret-key")
	srv, _ := New(&Config{}, zap.NewNop(), store)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/mgmt/ping", nil)
	rec := httptest.NewRecorder()
	authMiddleware(srv, next).ServeHTTP(rec, req)

	if !called {
		t.Fatal("/mgmt/ping should bypass auth")
	}
}

func TestRequirePermUsesAuthenticatedOperator(t *testing.T) {
	store := testKeyStore(t, "test-secret-key")
	srv, _ := New(&Config{}, zap.NewNop(), store)
	mgmt := &ManagementAPI{srv: srv}

	op := srv.auth.RegisterOperatorByName("default", auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/mgmt/sessions", nil)
	req = req.WithContext(context.WithValue(req.Context(), operatorCtxKey, op))
	rec := httptest.NewRecorder()

	if !mgmt.requirePerm(rec, req, auth.PermSessionList) {
		t.Fatal("authenticated admin should authorize session.list")
	}
}

func TestEnsureMgmtAPIKeyPersists(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/jager.db"
	os.Unsetenv("JAGER_MGMT_API_KEY")

	key1 := EnsureMgmtAPIKey(dir, dbPath, zap.NewNop())
	if key1 == "" {
		t.Fatal("expected generated key")
	}
	if os.Getenv("JAGER_MGMT_API_KEY") != key1 {
		t.Fatal("expected env to be set")
	}

	os.Unsetenv("JAGER_MGMT_API_KEY")
	key2 := EnsureMgmtAPIKey(dir, dbPath, zap.NewNop())
	if key1 != key2 {
		t.Fatalf("expected persisted key, got %q vs %q", key1, key2)
	}
}

func TestAPIKeyStoreConstantTimeValidate(t *testing.T) {
	store := testKeyStore(t, "correct-key")
	if _, ok := store.Validate("wrong-key"); ok {
		t.Fatal("wrong key should not validate")
	}
	if _, ok := store.Validate("correct-key"); !ok {
		t.Fatal("correct key should validate")
	}
}
