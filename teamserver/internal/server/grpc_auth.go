package server

import (
	"context"
	"strings"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type grpcCtxKey int

const grpcOperatorCtxKey grpcCtxKey = 1

// RBACInterceptor validates API keys and enforces method-level operator roles.
func RBACInterceptor(keyStore *APIKeyStore, authMgr *auth.AuthManager) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if keyStore == nil {
			return nil, status.Error(codes.Unauthenticated, "api key not configured")
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no metadata")
		}

		keys := md.Get("x-jager-api-key")
		if len(keys) == 0 {
			keys = md.Get("x-api-key")
		}
		if len(keys) == 0 {
			return nil, status.Error(codes.Unauthenticated, "no API key")
		}

		opKey, valid := keyStore.Validate(keys[0])
		if !valid {
			return nil, status.Error(codes.PermissionDenied, "invalid key")
		}

		role := authRoleFromString(opKey.Role)
		if perm, needsCheck := methodPermission(info.FullMethod); needsCheck {
			op := &auth.Operator{Name: opKey.Operator, Role: role}
			if authMgr != nil {
				if registered, err := authMgr.AuthenticateByName(opKey.Operator); err == nil {
					op = registered
				}
				if !authMgr.Authorize(op, perm) {
					return nil, status.Error(codes.PermissionDenied, "insufficient role")
				}
			} else if !roleAllows(authRoleFromString(opKey.Role), perm) {
				return nil, status.Error(codes.PermissionDenied, "insufficient role")
			}
		}
		if requiresAdmin(info.FullMethod) && role != auth.RoleAdmin {
			return nil, status.Error(codes.PermissionDenied, "admin required")
		}

		ctx = context.WithValue(ctx, grpcOperatorCtxKey, opKey.Operator)
		return handler(ctx, req)
	}
}

// UnaryAuthInterceptor validates x-api-key metadata (legacy wrapper).
func UnaryAuthInterceptor(keyStore *APIKeyStore) grpc.UnaryServerInterceptor {
	return RBACInterceptor(keyStore, nil)
}

func roleAllows(role auth.Role, perm auth.Permission) bool {
	perms, ok := auth.RolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

func requiresAdmin(fullMethod string) bool {
	switch fullMethod {
	case "/jagerpb.Jager/SetMalleableProfile":
		return true
	default:
		return false
	}
}

func methodPermission(fullMethod string) (auth.Permission, bool) {
	switch fullMethod {
	case "/jagerpb.Jager/GetSessions", "/jagerpb.Jager/GetBeacons", "/jagerpb.Jager/ListTasks",
		"/jagerpb.Jager/ListListeners", "/jagerpb.Jager/ListBuilds", "/jagerpb.Jager/ListCredentials",
		"/jagerpb.Jager/ListTargets", "/jagerpb.Jager/ListFindings", "/jagerpb.Jager/ListPivots",
		"/jagerpb.Jager/ListLoot", "/jagerpb.Jager/GetEngagementSummary", "/jagerpb.Jager/Ping":
		return auth.PermSessionList, true
	case "/jagerpb.Jager/QueueTask", "/jagerpb.Jager/CancelTask", "/jagerpb.Jager/WaitForTask":
		return auth.PermTaskCreate, true
	case "/jagerpb.Jager/KillSession", "/jagerpb.Jager/SetSleep":
		return auth.PermSessionKill, true
	case "/jagerpb.Jager/StartListener", "/jagerpb.Jager/StopListener":
		return auth.PermListenerCreate, true
	case "/jagerpb.Jager/GenerateImplant", "/jagerpb.Jager/GenerateStager", "/jagerpb.Jager/DownloadBuild":
		return auth.PermBuildImplant, true
	case "/jagerpb.Jager/AddCredential":
		return auth.PermCredAdd, true
	default:
		if strings.Contains(fullMethod, "Add") || strings.Contains(fullMethod, "Store") || strings.Contains(fullMethod, "Log") {
			return auth.PermTaskCreate, true
		}
		return "", false
	}
}
