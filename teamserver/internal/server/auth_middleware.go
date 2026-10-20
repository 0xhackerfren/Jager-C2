package server

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/auth"
)

type ctxKey int

const operatorCtxKey ctxKey = 1

// authMiddleware validates REST management API key and derives operator identity from it.
func authMiddleware(srv *Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mgmt/ping" {
			next.ServeHTTP(w, r)
			return
		}

		if srv == nil || srv.keyStore == nil {
			http.Error(w, `{"error":"API key not configured"}`, http.StatusForbidden)
			return
		}

		key := extractAPIKey(r)
		if key == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		opKey, valid := srv.keyStore.Validate(key)
		if !valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		if srv.auth != nil {
			if op, err := srv.auth.AuthenticateByName(opKey.Operator); err == nil {
				ctx = context.WithValue(ctx, operatorCtxKey, op)
			} else {
				role := authRoleFromString(opKey.Role)
				op := srv.auth.RegisterOperatorByName(opKey.Operator, role)
				ctx = context.WithValue(ctx, operatorCtxKey, op)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractAPIKey(r *http.Request) string {
	key := strings.TrimSpace(r.Header.Get("X-Jager-C2-Api-Key"))
	if key == "" {
		authHdr := r.Header.Get("Authorization")
		if strings.HasPrefix(authHdr, "Bearer ") {
			key = strings.TrimSpace(strings.TrimPrefix(authHdr, "Bearer "))
		}
	}
	return key
}

func validateAPIKey(store *APIKeyStore, key string) bool {
	if store == nil {
		return false
	}
	_, ok := store.Validate(key)
	return ok
}

func constantTimeKeyMatch(got, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func (m *ManagementAPI) requirePerm(w http.ResponseWriter, r *http.Request, perm auth.Permission) bool {
	if m.srv.auth == nil {
		return true
	}
	op, _ := r.Context().Value(operatorCtxKey).(*auth.Operator)
	if op == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if !m.srv.auth.Authorize(op, perm) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (m *ManagementAPI) AuthenticatedHandler() http.Handler {
	return authMiddleware(m.srv, m.Handler())
}

func operatorFromContext(ctx context.Context) *auth.Operator {
	op, _ := ctx.Value(operatorCtxKey).(*auth.Operator)
	return op
}
