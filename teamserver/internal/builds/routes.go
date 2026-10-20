package builds

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/malleable"
)

type routeKind string

const (
	RouteCheckin  routeKind = "checkin"
	RouteRegister routeKind = "register"
	RouteResult   routeKind = "result"
	RouteStage    routeKind = "stage"
	RouteTunnel   routeKind = "tunnel"
)

type routeEntry struct {
	kind    routeKind
	buildID string
	profile *malleable.Profile
}

var (
	routeMu sync.RWMutex
	routes  = map[string]routeEntry{}
)

// RegisterMalleableRoutes maps mutated profile paths (legacy, no per-path profile).
func RegisterMalleableRoutes(checkin, register, result, stage, tunnel string) {
	RegisterMalleableRoutesForBuild("", checkin, register, result, stage, tunnel, nil)
}

// RegisterMalleableRoutesForBuild registers paths for a build with optional wire profile.
// Paths that coincide with default URIs are still registered when a profile is
// provided so that malleable transforms are applied correctly for that build.
func RegisterMalleableRoutesForBuild(buildID, checkin, register, result, stage, tunnel string, profile *malleable.Profile) {
	routeMu.Lock()
	defer routeMu.Unlock()
	for path, kind := range map[string]routeKind{
		checkin:  RouteCheckin,
		register: RouteRegister,
		result:   RouteResult,
		stage:    RouteStage,
		tunnel:   RouteTunnel,
	} {
		path = normalizeRoutePath(path)
		if path == "" {
			continue
		}
		routes[path] = routeEntry{kind: kind, buildID: buildID, profile: profile}
	}
}

// LoadAndRegisterMalleableProfile loads JSON profile and registers routes for a build.
func LoadAndRegisterMalleableProfile(buildID, malleableJSONPath, checkin, register, result, stage, tunnel string) error {
	var profile *malleable.Profile
	if malleableJSONPath != "" {
		raw, err := os.ReadFile(malleableJSONPath)
		if err == nil {
			var p malleable.Profile
			if json.Unmarshal(raw, &p) == nil {
				profile = &p
			}
		}
	}
	RegisterMalleableRoutesForBuild(buildID, checkin, register, result, stage, tunnel, profile)
	return nil
}

func normalizeRoutePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

var defaultImplantPaths = map[string]struct{}{
	"/api/v1/checkin": {},
	"/api/v1/register": {},
	"/api/v1/result":   {},
	"/api/v1/tunnel":   {},
	"/api/v1/stage":    {},
}

// IsDefaultImplantPath reports whether path is the built-in un-mutated listener URI.
func IsDefaultImplantPath(path string) bool {
	_, ok := defaultImplantPaths[normalizeRoutePath(path)]
	return ok
}

// LookupRoute returns handler kind for a request path (exact match).
func LookupRoute(path string) (routeKind, bool) {
	routeMu.RLock()
	defer routeMu.RUnlock()
	entry, ok := routes[normalizeRoutePath(path)]
	if !ok {
		return "", false
	}
	return entry.kind, true
}

// LookupProfileForPath returns the malleable profile bound to this URI path.
func LookupProfileForPath(path string) (*malleable.Profile, bool) {
	routeMu.RLock()
	defer routeMu.RUnlock()
	entry, ok := routes[normalizeRoutePath(path)]
	if !ok || entry.profile == nil {
		return nil, false
	}
	return entry.profile, true
}

// MalleableDispatch routes mutated profile URIs to standard handlers.
type MalleableDispatch struct {
	Checkin  http.HandlerFunc
	Register http.HandlerFunc
	Result   http.HandlerFunc
	Stage    http.HandlerFunc
	Tunnel   http.HandlerFunc
	Default  http.HandlerFunc
}

func (d MalleableDispatch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if kind, ok := LookupRoute(r.URL.Path); ok {
		switch kind {
		case RouteCheckin:
			d.Checkin(w, r)
			return
		case RouteRegister:
			d.Register(w, r)
			return
		case RouteResult:
			d.Result(w, r)
			return
		case RouteStage:
			d.Stage(w, r)
			return
		case RouteTunnel:
			if d.Tunnel != nil {
				d.Tunnel(w, r)
				return
			}
		}
	}
	if d.Default != nil {
		d.Default(w, r)
		return
	}
	http.NotFound(w, r)
}
