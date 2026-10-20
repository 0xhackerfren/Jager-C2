package jagerpb

import (
	"context"

	"google.golang.org/grpc"
)

// JagerServer is the gRPC service interface
type JagerServer interface {
	Ping(context.Context, *Request) (*Status, error)
	GetSessions(context.Context, *SessionsRequest) (*SessionsResponse, error)
	GetBeacons(context.Context, *BeaconsRequest) (*BeaconsResponse, error)
	InteractSession(context.Context, *InteractRequest) (*SessionResponse, error)
	KillSession(context.Context, *KillRequest) (*Status, error)
	RenameSession(context.Context, *RenameRequest) (*Status, error)
	SetSleep(context.Context, *SleepRequest) (*Status, error)
	QueueTask(context.Context, *TaskRequest) (*TaskResponse, error)
	ListTasks(context.Context, *TasksListRequest) (*TasksListResponse, error)
	CancelTask(context.Context, *TaskCancelRequest) (*Status, error)
	WaitForTask(context.Context, *TaskRequest) (*TaskResponse, error)
	StartListener(context.Context, *StartListenerRequest) (*ListenerResponse, error)
	StopListener(context.Context, *StopListenerRequest) (*Status, error)
	ListListeners(context.Context, *ListListenersRequest) (*ListenersResponse, error)
	SetMalleableProfile(context.Context, *SetProfileRequest) (*Status, error)
	GenerateImplant(context.Context, *GenerateImplantRequest) (*GenerateResponse, error)
	GenerateStager(context.Context, *GenerateStagerRequest) (*GenerateResponse, error)
	ListBuilds(context.Context, *ListBuildsRequest) (*BuildsResponse, error)
	DownloadBuild(context.Context, *DownloadBuildRequest) (*BuildDataResponse, error)
	AddCredential(context.Context, *AddCredentialRequest) (*Status, error)
	ListCredentials(context.Context, *ListCredentialsRequest) (*CredentialsResponse, error)
	AddTarget(context.Context, *AddTargetRequest) (*Status, error)
	ListTargets(context.Context, *ListTargetsRequest) (*TargetsResponse, error)
	AddFinding(context.Context, *AddFindingRequest) (*Status, error)
	ListFindings(context.Context, *ListFindingsRequest) (*FindingsResponse, error)
	AddPivot(context.Context, *AddPivotRequest) (*Status, error)
	ListPivots(context.Context, *ListPivotsRequest) (*PivotsResponse, error)
	StoreLoot(context.Context, *StoreLootRequest) (*Status, error)
	ListLoot(context.Context, *ListLootRequest) (*LootResponse, error)
	LogAccess(context.Context, *LogAccessRequest) (*Status, error)
	LogTechnique(context.Context, *LogTechniqueRequest) (*Status, error)
	GetEngagementSummary(context.Context, *SummaryRequest) (*EngagementSummary, error)
}

// UnimplementedJagerServer provides default implementations that return unimplemented errors.
// Embed this in your server impl to get forward compatibility.
type UnimplementedJagerServer struct{}

func (UnimplementedJagerServer) Ping(context.Context, *Request) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) GetSessions(context.Context, *SessionsRequest) (*SessionsResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) GetBeacons(context.Context, *BeaconsRequest) (*BeaconsResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) InteractSession(context.Context, *InteractRequest) (*SessionResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) KillSession(context.Context, *KillRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) RenameSession(context.Context, *RenameRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) SetSleep(context.Context, *SleepRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) QueueTask(context.Context, *TaskRequest) (*TaskResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) ListTasks(context.Context, *TasksListRequest) (*TasksListResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) CancelTask(context.Context, *TaskCancelRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) WaitForTask(context.Context, *TaskRequest) (*TaskResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) StartListener(context.Context, *StartListenerRequest) (*ListenerResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) StopListener(context.Context, *StopListenerRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) ListListeners(context.Context, *ListListenersRequest) (*ListenersResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) SetMalleableProfile(context.Context, *SetProfileRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) GenerateImplant(context.Context, *GenerateImplantRequest) (*GenerateResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) GenerateStager(context.Context, *GenerateStagerRequest) (*GenerateResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) ListBuilds(context.Context, *ListBuildsRequest) (*BuildsResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) DownloadBuild(context.Context, *DownloadBuildRequest) (*BuildDataResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) AddCredential(context.Context, *AddCredentialRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) ListCredentials(context.Context, *ListCredentialsRequest) (*CredentialsResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) AddTarget(context.Context, *AddTargetRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) ListTargets(context.Context, *ListTargetsRequest) (*TargetsResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) AddFinding(context.Context, *AddFindingRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) ListFindings(context.Context, *ListFindingsRequest) (*FindingsResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) AddPivot(context.Context, *AddPivotRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) ListPivots(context.Context, *ListPivotsRequest) (*PivotsResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) StoreLoot(context.Context, *StoreLootRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) ListLoot(context.Context, *ListLootRequest) (*LootResponse, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) LogAccess(context.Context, *LogAccessRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) LogTechnique(context.Context, *LogTechniqueRequest) (*Status, error) {
	return nil, grpc.ErrServerStopped
}
func (UnimplementedJagerServer) GetEngagementSummary(context.Context, *SummaryRequest) (*EngagementSummary, error) {
	return nil, grpc.ErrServerStopped
}

// RegisterJagerServer registers the service implementation with a gRPC server.
// This is a simplified version -- real proto codegen generates full service descriptors.
// For our use case, the RPC server registers handlers directly.
func RegisterJagerServer(s *grpc.Server, srv JagerServer) {
	// In a real proto-generated setup this registers a ServiceDesc.
	// Since we use direct handler registration via our RPCServer,
	// this is a no-op placeholder that satisfies the compile contract.
	_ = s
	_ = srv
}
