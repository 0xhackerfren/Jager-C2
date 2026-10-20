package sessions

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/crypto"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/events"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Session wraps protobuf session state with optional per-session wire crypto.
type Session struct {
	Data   *pb.Session
	Crypto *crypto.SessionCrypto
}

type Manager struct {
	mu           sync.RWMutex
	sessions     map[string]*Session
	beacons      map[string]*pb.Beacon
	logger       *zap.Logger
	events       *events.Bus
	taskPurge    TaskPurger
	pivotClean   PivotCleaner
	db           *sql.DB
}

// TaskPurger removes queued tasks when a session is killed.
type TaskPurger interface {
	PurgeSessionTasks(sessionID string)
}

// PivotCleaner stops all pivots/portforwards for a dead session.
type PivotCleaner interface {
	StopAllForSession(sessionID string)
}

func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		beacons:  make(map[string]*pb.Beacon),
		logger:   logger,
	}
}

func (m *Manager) SetEventBus(bus *events.Bus) {
	m.events = bus
}

func (m *Manager) SetTaskPurger(purger TaskPurger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.taskPurge = purger
}

func (m *Manager) SetPivotCleaner(cleaner PivotCleaner) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pivotClean = cleaner
}

func (m *Manager) RegisterSession(reg *pb.ImplantRegistration, sessionCrypto *crypto.SessionCrypto) *pb.Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.sessions[reg.ImplantId]; ok {
		previousState := "alive"
		if !existing.Data.Alive {
			previousState = "dead"
		}
		if existing.Crypto != nil {
			existing.Crypto.Invalidate()
		}
		m.logger.Info("session re-registered (reconnect)",
			zap.String("id", reg.ImplantId),
			zap.String("previous_state", previousState),
		)
		go m.RecordReconnect(reg.ImplantId, previousState)
	}

	sess := &Session{
		Data: &pb.Session{
			Id:              reg.ImplantId,
			Registration:    reg,
			LastCheckin:     timestamppb.Now(),
			Alive:           true,
			ActiveTransport: reg.Transport,
			RemoteAddr:      reg.InternalIp,
		},
		Crypto: sessionCrypto,
	}

	if sessionCrypto != nil && reg.ImplantId != "" {
		sessionCrypto.SetSessionID(reg.ImplantId)
	}

	m.sessions[sess.Data.Id] = sess
	m.logger.Info("session registered",
		zap.String("id", sess.Data.Id),
		zap.String("hostname", reg.Hostname),
		zap.String("user", reg.Username),
		zap.Bool("elevated", reg.Elevated),
		zap.Bool("crypto", sessionCrypto != nil && sessionCrypto.Initialized),
	)
	if m.events != nil {
		m.events.Publish(events.Event{
			Type:      events.EventSessionNew,
			SessionID: sess.Data.Id,
			Data: map[string]interface{}{
				"hostname": reg.Hostname,
				"username": reg.Username,
				"elevated": reg.Elevated,
			},
		})
	}
	go m.PersistSession(sess.Data)
	return sess.Data
}

func (m *Manager) RegisterBeacon(reg *pb.ImplantRegistration, interval, jitter uint32) *pb.Beacon {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	next := now.Add(time.Duration(interval) * time.Second)

	beacon := &pb.Beacon{
		Id:              reg.ImplantId,
		Registration:    reg,
		LastCheckin:     timestamppb.New(now),
		NextCheckin:     timestamppb.New(next),
		IntervalSeconds: interval,
		JitterPercent:   jitter,
		Alive:           true,
		ActiveTransport: reg.Transport,
		RemoteAddr:      reg.InternalIp,
	}

	m.beacons[beacon.Id] = beacon
	m.logger.Info("beacon registered",
		zap.String("id", beacon.Id),
		zap.String("hostname", reg.Hostname),
		zap.Uint32("interval", interval),
	)
	go m.PersistBeacon(beacon)
	return beacon
}

func (m *Manager) SetSessionCrypto(id string, sessionCrypto *crypto.SessionCrypto) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.sessions[id]; ok {
		entry.Crypto = sessionCrypto
		return
	}

	// Session may not exist yet if callers attach crypto before RegisterSession.
	m.sessions[id] = &Session{
		Data: &pb.Session{
			Id:    id,
			Alive: true,
		},
		Crypto: sessionCrypto,
	}
}

func (m *Manager) GetSessionCrypto(id string) *crypto.SessionCrypto {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if entry, ok := m.sessions[id]; ok {
		return entry.Crypto
	}
	return nil
}

// DecryptBySessionPrefix routes decryption using the 16-byte session ID hash prefix.
func (m *Manager) DecryptBySessionPrefix(packet []byte) (sessionID string, plaintext []byte, err error) {
	if len(packet) < crypto.SessionIDHashSize+crypto.HeaderSize() {
		return "", nil, fmt.Errorf("encrypted packet too short for session prefix")
	}

	prefix := packet[:crypto.SessionIDHashSize]

	m.mu.RLock()
	defer m.mu.RUnlock()

	for id, entry := range m.sessions {
		if entry.Crypto == nil || !entry.Crypto.Ready() || !entry.Crypto.HasSessionID {
			continue
		}
		if !bytes.Equal(entry.Crypto.SessionIDHash[:], prefix) {
			continue
		}
		pt, decErr := entry.Crypto.Decrypt(append([]byte(nil), packet...))
		if decErr == nil {
			return id, pt, nil
		}
		return "", nil, decErr
	}
	return "", nil, fmt.Errorf("no session matches encrypted prefix")
}

func (m *Manager) Checkin(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.sessions[id]; ok {
		entry.Data.LastCheckin = timestamppb.Now()
		entry.Data.Alive = true
		if m.events != nil {
			m.events.Publish(events.Event{Type: events.EventSessionCheckin, SessionID: id})
		}
		go m.UpdateCheckin(id)
		return nil
	}
	if beacon, ok := m.beacons[id]; ok {
		now := time.Now()
		beacon.LastCheckin = timestamppb.New(now)
		next := now.Add(time.Duration(beacon.IntervalSeconds) * time.Second)
		beacon.NextCheckin = timestamppb.New(next)
		beacon.Alive = true
		if m.events != nil {
			m.events.Publish(events.Event{Type: events.EventSessionCheckin, SessionID: id})
		}
		go m.UpdateCheckin(id)
		return nil
	}
	return fmt.Errorf("unknown session/beacon: %s", id)
}

func (m *Manager) GetSession(id string) (*pb.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if entry, ok := m.sessions[id]; ok {
		return entry.Data, nil
	}
	return nil, fmt.Errorf("session not found: %s", id)
}

func (m *Manager) GetSessions(aliveOnly bool) []*pb.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*pb.Session
	for _, entry := range m.sessions {
		if entry.Data == nil {
			continue
		}
		if aliveOnly && !entry.Data.Alive {
			continue
		}
		result = append(result, entry.Data)
	}
	return result
}

func (m *Manager) GetBeacons(aliveOnly bool) []*pb.Beacon {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*pb.Beacon
	for _, b := range m.beacons {
		if aliveOnly && !b.Alive {
			continue
		}
		result = append(result, b)
	}
	return result
}

func (m *Manager) Kill(id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.sessions[id]; ok {
		if entry.Crypto != nil {
			entry.Crypto.Invalidate()
		}
		entry.Data.Alive = false
		if m.taskPurge != nil {
			m.taskPurge.PurgeSessionTasks(id)
		}
		if m.pivotClean != nil {
			go m.pivotClean.StopAllForSession(id)
		}
		m.logger.Info("session killed", zap.String("id", id))
		if m.events != nil {
			m.events.Publish(events.Event{Type: events.EventSessionDead, SessionID: id})
		}
		go m.MarkKilled(id)
		return nil
	}
	if beacon, ok := m.beacons[id]; ok {
		beacon.Alive = false
		if m.taskPurge != nil {
			m.taskPurge.PurgeSessionTasks(id)
		}
		if m.pivotClean != nil {
			go m.pivotClean.StopAllForSession(id)
		}
		m.logger.Info("beacon killed", zap.String("id", id))
		if m.events != nil {
			m.events.Publish(events.Event{Type: events.EventSessionDead, SessionID: id})
		}
		go m.MarkKilled(id)
		return nil
	}
	return fmt.Errorf("session/beacon not found: %s", id)
}

func (m *Manager) Rename(id, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.sessions[id]; ok {
		entry.Data.Note = name
		return nil
	}
	if beacon, ok := m.beacons[id]; ok {
		beacon.Note = name
		return nil
	}
	return fmt.Errorf("session/beacon not found: %s", id)
}

func (m *Manager) SessionExists(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, inSess := m.sessions[id]
	_, inBeacon := m.beacons[id]
	return inSess || inBeacon
}

func (m *Manager) GetActiveCount() (sessions int, beacons int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, entry := range m.sessions {
		if entry.Data != nil && entry.Data.Alive {
			sessions++
		}
	}
	for _, b := range m.beacons {
		if b.Alive {
			beacons++
		}
	}
	return
}

// StartHeartbeatMonitor checks for stale sessions/beacons periodically.
// A beacon is considered dead if it misses (interval * missedMultiplier) seconds.
func (m *Manager) StartHeartbeatMonitor(ctx context.Context, missedMultiplier uint32) {
	if missedMultiplier == 0 {
		missedMultiplier = 3
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkStale(missedMultiplier)
		}
	}
}

func (m *Manager) checkStale(missedMultiplier uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	for id, entry := range m.sessions {
		if entry.Data == nil || !entry.Data.Alive {
			continue
		}
		lastSeen := entry.Data.LastCheckin.AsTime()
		if now.Sub(lastSeen) > 5*time.Minute {
			entry.Data.Alive = false
			m.logger.Warn("session timed out", zap.String("id", id),
				zap.Duration("since_last_checkin", now.Sub(lastSeen)))
			if m.taskPurge != nil {
				m.taskPurge.PurgeSessionTasks(id)
			}
			if m.pivotClean != nil {
				go m.pivotClean.StopAllForSession(id)
			}
			if m.events != nil {
				m.events.Publish(events.Event{Type: events.EventSessionDead, SessionID: id, Data: "timeout"})
			}
		}
	}

	for id, beacon := range m.beacons {
		if !beacon.Alive {
			continue
		}
		lastSeen := beacon.LastCheckin.AsTime()
		timeout := time.Duration(beacon.IntervalSeconds*missedMultiplier) * time.Second
		if now.Sub(lastSeen) > timeout {
			beacon.Alive = false
			m.logger.Warn("beacon timed out", zap.String("id", id),
				zap.Duration("timeout", timeout),
				zap.Duration("since_last_checkin", now.Sub(lastSeen)))
			if m.taskPurge != nil {
				m.taskPurge.PurgeSessionTasks(id)
			}
			if m.pivotClean != nil {
				go m.pivotClean.StopAllForSession(id)
			}
			if m.events != nil {
				m.events.Publish(events.Event{Type: events.EventSessionDead, SessionID: id, Data: "timeout"})
			}
		}
	}
}
