package server

import (
	"context"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/builds"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type RPCServer struct {
	pb.UnimplementedJagerServer
	srv *Server
}

func NewRPCServer(srv *Server) *RPCServer {
	return &RPCServer{srv: srv}
}

func (r *RPCServer) Register(s *grpc.Server) {
	pb.RegisterJagerServer(s, r)
}

// --- Health ---

func (r *RPCServer) Ping(ctx context.Context, req *pb.Request) (*pb.Status, error) {
	return &pb.Status{Success: true}, nil
}

// --- Sessions ---

func (r *RPCServer) GetSessions(ctx context.Context, req *pb.SessionsRequest) (*pb.SessionsResponse, error) {
	all := r.srv.sessions.GetSessions(req.AliveOnly)
	return &pb.SessionsResponse{Sessions: all}, nil
}

func (r *RPCServer) GetBeacons(ctx context.Context, req *pb.BeaconsRequest) (*pb.BeaconsResponse, error) {
	all := r.srv.sessions.GetBeacons(req.AliveOnly)
	return &pb.BeaconsResponse{Beacons: all}, nil
}

func (r *RPCServer) InteractSession(ctx context.Context, req *pb.InteractRequest) (*pb.SessionResponse, error) {
	sess, err := r.srv.sessions.GetSession(req.SessionId)
	if err != nil {
		return &pb.SessionResponse{Status: &pb.Status{Success: false, Error: err.Error()}}, nil
	}
	return &pb.SessionResponse{Session: sess, Status: &pb.Status{Success: true}}, nil
}

func (r *RPCServer) KillSession(ctx context.Context, req *pb.KillRequest) (*pb.Status, error) {
	err := r.srv.sessions.Kill(req.Id, req.Force)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) RenameSession(ctx context.Context, req *pb.RenameRequest) (*pb.Status, error) {
	err := r.srv.sessions.Rename(req.Id, req.NewName)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) SetSleep(ctx context.Context, req *pb.SleepRequest) (*pb.Status, error) {
	err := r.srv.tasks.QueueSleepChange(req.Id, req.IntervalSeconds, req.JitterPercent)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

// --- Tasks ---

func (r *RPCServer) QueueTask(ctx context.Context, req *pb.TaskRequest) (*pb.TaskResponse, error) {
	task := &pb.Task{
		Id:          uuid.New().String(),
		SessionId:   req.SessionId,
		Type:        req.Type,
		State:       pb.TaskState_TASK_STATE_QUEUED,
		RequestData: req.Data,
		CreatedAt:   timestamppb.Now(),
		CreatedBy:   req.Request.GetOperator(),
	}

	err := r.srv.tasks.Enqueue(task)
	if err != nil {
		return &pb.TaskResponse{Status: &pb.Status{Success: false, Error: err.Error()}}, nil
	}
	return &pb.TaskResponse{Task: task, Status: &pb.Status{Success: true}}, nil
}

func (r *RPCServer) ListTasks(ctx context.Context, req *pb.TasksListRequest) (*pb.TasksListResponse, error) {
	tasks := r.srv.tasks.List(req.SessionId, req.FilterState, req.Limit)
	return &pb.TasksListResponse{Tasks: tasks}, nil
}

func (r *RPCServer) CancelTask(ctx context.Context, req *pb.TaskCancelRequest) (*pb.Status, error) {
	err := r.srv.tasks.Cancel(req.TaskId)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) WaitForTask(ctx context.Context, req *pb.TaskRequest) (*pb.TaskResponse, error) {
	timeout := time.After(120 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	taskID := string(req.Data) // Task ID passed in data field for wait
	for {
		select {
		case <-ctx.Done():
			return &pb.TaskResponse{Status: &pb.Status{Success: false, Error: "context cancelled"}}, nil
		case <-timeout:
			return &pb.TaskResponse{Status: &pb.Status{Success: false, Error: "timeout waiting for task"}}, nil
		case <-ticker.C:
			task, err := r.srv.tasks.Get(taskID)
			if err != nil {
				return &pb.TaskResponse{Status: &pb.Status{Success: false, Error: err.Error()}}, nil
			}
			if task.State == pb.TaskState_TASK_STATE_COMPLETED || task.State == pb.TaskState_TASK_STATE_FAILED {
				return &pb.TaskResponse{Task: task, Status: &pb.Status{Success: true}}, nil
			}
		}
	}
}

// --- Listeners ---

func (r *RPCServer) StartListener(ctx context.Context, req *pb.StartListenerRequest) (*pb.ListenerResponse, error) {
	cfg := req.Config
	if cfg.Id == "" {
		cfg.Id = uuid.New().String()
	}
	cfg.StartedAt = timestamppb.Now()

	err := r.srv.listen.Start(cfg)
	if err != nil {
		return &pb.ListenerResponse{Status: &pb.Status{Success: false, Error: err.Error()}}, nil
	}
	return &pb.ListenerResponse{Listener: cfg, Status: &pb.Status{Success: true}}, nil
}

func (r *RPCServer) StopListener(ctx context.Context, req *pb.StopListenerRequest) (*pb.Status, error) {
	err := r.srv.listen.Stop(req.ListenerId)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) ListListeners(ctx context.Context, req *pb.ListListenersRequest) (*pb.ListenersResponse, error) {
	all := r.srv.listen.List()
	return &pb.ListenersResponse{Listeners: all}, nil
}

func (r *RPCServer) SetMalleableProfile(ctx context.Context, req *pb.SetProfileRequest) (*pb.Status, error) {
	err := r.srv.listen.SetProfile(req.ListenerId, req.Profile)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

// --- Builds ---

func (r *RPCServer) GenerateImplant(ctx context.Context, req *pb.GenerateImplantRequest) (*pb.GenerateResponse, error) {
	cfg := req.Config
	if cfg == nil {
		cfg = &pb.ImplantConfig{}
	}
	br := builds.BuildRequest{
		C2URL:       cfg.C2Url,
		Format:      formatToString(cfg.Format),
		Arch:        cfg.Arch,
		Sleep:       int(cfg.Sleep),
		Jitter:      int(cfg.Jitter),
		Polymorphic: true,
	}
	result, err := r.srv.engine.GenerateImplant(br)
	if err != nil {
		return &pb.GenerateResponse{Status: &pb.Status{Success: false, Error: err.Error()}}, nil
	}
	savePath := req.SavePath
	if savePath == "" {
		if p, ok := result.Implant["path"].(string); ok {
			savePath = p
		}
	}
	return &pb.GenerateResponse{
		BuildId:  result.BuildID,
		SavePath: savePath,
		Status:   &pb.Status{Success: true},
	}, nil
}

func (r *RPCServer) GenerateStager(ctx context.Context, req *pb.GenerateStagerRequest) (*pb.GenerateResponse, error) {
	cfg := req.Config
	if cfg == nil {
		cfg = &pb.StagerConfig{}
	}
	br := builds.BuildRequest{
		C2URL:        cfg.StageUrl,
		ImplantBuild: cfg.IocProfile, // reuse field for implant_build_id when set via REST
	}
	result, err := r.srv.engine.GenerateStager(br)
	if err != nil {
		return &pb.GenerateResponse{Status: &pb.Status{Success: false, Error: err.Error()}}, nil
	}
	savePath := req.SavePath
	if savePath == "" {
		if p, ok := result.Stager["path"].(string); ok {
			savePath = p
		}
	}
	return &pb.GenerateResponse{
		BuildId:  result.BuildID,
		SavePath: savePath,
		Status:   &pb.Status{Success: true},
	}, nil
}

func formatToString(f pb.PayloadFormat) string {
	switch f {
	case pb.PayloadFormat_FORMAT_DLL:
		return "dll"
	case pb.PayloadFormat_FORMAT_SHELLCODE:
		return "shellcode"
	default:
		return "exe"
	}
}

func (r *RPCServer) ListBuilds(ctx context.Context, req *pb.ListBuildsRequest) (*pb.BuildsResponse, error) {
	recs := r.srv.builds.List()
	ids := make([]string, 0, len(recs))
	for _, rec := range recs {
		ids = append(ids, rec.ID)
	}
	return &pb.BuildsResponse{Builds: ids}, nil
}

func (r *RPCServer) DownloadBuild(ctx context.Context, req *pb.DownloadBuildRequest) (*pb.BuildDataResponse, error) {
	data, err := r.srv.builds.GetBuildData(req.BuildId)
	if err != nil {
		return &pb.BuildDataResponse{Status: &pb.Status{Success: false, Error: err.Error()}}, nil
	}
	return &pb.BuildDataResponse{
		Data:   data,
		Status: &pb.Status{Success: true},
	}, nil
}

// --- Loot ---

func (r *RPCServer) AddCredential(ctx context.Context, req *pb.AddCredentialRequest) (*pb.Status, error) {
	err := r.srv.loot.AddCredential(req.Credential)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) ListCredentials(ctx context.Context, req *pb.ListCredentialsRequest) (*pb.CredentialsResponse, error) {
	creds, err := r.srv.loot.ListCredentials(req.DomainFilter, req.TypeFilter)
	if err != nil {
		return nil, err
	}
	return &pb.CredentialsResponse{Credentials: creds}, nil
}

func (r *RPCServer) AddTarget(ctx context.Context, req *pb.AddTargetRequest) (*pb.Status, error) {
	err := r.srv.loot.AddTarget(req.Target)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) ListTargets(ctx context.Context, req *pb.ListTargetsRequest) (*pb.TargetsResponse, error) {
	targets, err := r.srv.loot.ListTargets(req.CompromisedOnly)
	if err != nil {
		return nil, err
	}
	return &pb.TargetsResponse{Targets: targets}, nil
}

func (r *RPCServer) AddFinding(ctx context.Context, req *pb.AddFindingRequest) (*pb.Status, error) {
	err := r.srv.loot.AddFinding(req.Finding)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) ListFindings(ctx context.Context, req *pb.ListFindingsRequest) (*pb.FindingsResponse, error) {
	findings, err := r.srv.loot.ListFindings(req.SeverityFilter)
	if err != nil {
		return nil, err
	}
	return &pb.FindingsResponse{Findings: findings}, nil
}

func (r *RPCServer) AddPivot(ctx context.Context, req *pb.AddPivotRequest) (*pb.Status, error) {
	err := r.srv.loot.AddPivot(req.Pivot)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) ListPivots(ctx context.Context, req *pb.ListPivotsRequest) (*pb.PivotsResponse, error) {
	pivots, err := r.srv.loot.ListPivots(req.ActiveOnly)
	if err != nil {
		return nil, err
	}
	return &pb.PivotsResponse{Pivots: pivots}, nil
}

func (r *RPCServer) StoreLoot(ctx context.Context, req *pb.StoreLootRequest) (*pb.Status, error) {
	err := r.srv.loot.StoreLoot(req.Loot)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) ListLoot(ctx context.Context, req *pb.ListLootRequest) (*pb.LootResponse, error) {
	items, err := r.srv.loot.ListLoot(req.Category)
	if err != nil {
		return nil, err
	}
	return &pb.LootResponse{Items: items}, nil
}

func (r *RPCServer) LogAccess(ctx context.Context, req *pb.LogAccessRequest) (*pb.Status, error) {
	err := r.srv.loot.LogAccess(req.Entry)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) LogTechnique(ctx context.Context, req *pb.LogTechniqueRequest) (*pb.Status, error) {
	err := r.srv.loot.LogTechnique(req.Entry)
	if err != nil {
		return &pb.Status{Success: false, Error: err.Error()}, nil
	}
	return &pb.Status{Success: true}, nil
}

func (r *RPCServer) GetEngagementSummary(ctx context.Context, req *pb.SummaryRequest) (*pb.EngagementSummary, error) {
	return r.srv.loot.GetSummary(r.srv.sessions, r.srv.listen)
}
