package listeners

import (
	"fmt"
	"sync"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/events"
	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/sessions"
	"go.uber.org/zap"
)

type Listener interface {
	Start() error
	Stop() error
	ID() string
	Config() *pb.ListenerConfig
}

type Manager struct {
	mu        sync.RWMutex
	listeners map[string]Listener
	configs   map[string]*pb.ListenerConfig
	profiles  map[string]*pb.MalleableProfile
	sessions  *sessions.Manager
	tasks     TaskQueue
	builds    BuildStore
	tunnels   TunnelManager
	logger    *zap.Logger
	events    *events.Bus
}

func NewManager(logger *zap.Logger, sessions *sessions.Manager, tq TaskQueue, bs BuildStore) *Manager {
	return &Manager{
		listeners: make(map[string]Listener),
		configs:   make(map[string]*pb.ListenerConfig),
		profiles:  make(map[string]*pb.MalleableProfile),
		sessions:  sessions,
		tasks:     tq,
		builds:    bs,
		logger:    logger,
	}
}

func (m *Manager) SetEventBus(bus *events.Bus) {
	m.events = bus
}

func (m *Manager) Start(cfg *pb.ListenerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[cfg.Id]; exists {
		return fmt.Errorf("listener already running: %s", cfg.Id)
	}

	var lis Listener
	var err error

	switch cfg.Transport {
	case pb.Transport_TRANSPORT_HTTPS:
		lis, err = NewHTTPSListener(cfg, m.sessions, m.tasks, m.builds, m.logger)
		if err == nil && m.tunnels != nil {
			if hl, ok := lis.(*HTTPSListener); ok {
				hl.SetTunnelManager(m.tunnels)
			}
		}
	case pb.Transport_TRANSPORT_DNS:
		lis, err = NewDNSListener(cfg, m.sessions, m.tasks, m.builds, m.logger)
	case pb.Transport_TRANSPORT_TCP:
		if len(cfg.Id) >= 5 && cfg.Id[:5] == "extc2" {
			lis, err = NewExternalC2Listener(cfg, m.sessions, m.tasks, m.logger)
		} else {
			lis, err = NewTCPListener(cfg, m.sessions, m.tasks, m.builds, m.logger)
		}
	case pb.Transport_TRANSPORT_SMB:
		lis, err = NewSMBListener(cfg, m.sessions, m.tasks, m.builds, m.logger)
	default:
		return fmt.Errorf("unknown transport: %v", cfg.Transport)
	}

	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	if err := lis.Start(); err != nil {
		return fmt.Errorf("start listener: %w", err)
	}

	if hl, ok := lis.(*HTTPSListener); ok {
		if pbProf, ok := m.profiles[cfg.Id]; ok && pbProf != nil {
			if p, err := malleableProfileFromPB(pbProf); err == nil && p != nil {
				hl.SetMalleableProfile(p)
			}
		}
	}

	m.listeners[cfg.Id] = lis
	m.configs[cfg.Id] = cfg

	m.logger.Info("listener started",
		zap.String("id", cfg.Id),
		zap.String("transport", cfg.Transport.String()),
		zap.String("bind", fmt.Sprintf("%s:%d", cfg.BindHost, cfg.BindPort)),
	)
	if m.events != nil {
		m.events.Publish(events.Event{
			Type: events.EventListenerStart,
			Data: map[string]interface{}{
				"listener_id": cfg.Id,
				"transport":   cfg.Transport.String(),
				"bind_host":   cfg.BindHost,
				"bind_port":   cfg.BindPort,
			},
		})
	}
	return nil
}

func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lis, ok := m.listeners[id]
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}

	if err := lis.Stop(); err != nil {
		return err
	}

	delete(m.listeners, id)
	delete(m.configs, id)
	m.logger.Info("listener stopped", zap.String("id", id))
	if m.events != nil {
		m.events.Publish(events.Event{
			Type: events.EventListenerStop,
			Data: map[string]interface{}{"listener_id": id},
		})
	}
	return nil
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, lis := range m.listeners {
		if err := lis.Stop(); err != nil {
			m.logger.Error("failed to stop listener", zap.String("id", id), zap.Error(err))
		}
	}
	m.listeners = make(map[string]Listener)
	m.configs = make(map[string]*pb.ListenerConfig)
}

func (m *Manager) List() []*pb.ListenerConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*pb.ListenerConfig
	for _, cfg := range m.configs {
		result = append(result, cfg)
	}
	return result
}

func (m *Manager) SetProfile(listenerID string, profile *pb.MalleableProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.configs[listenerID]; !ok {
		return fmt.Errorf("listener not found: %s", listenerID)
	}
	m.profiles[listenerID] = profile
	if lis, ok := m.listeners[listenerID]; ok {
		if hl, ok := lis.(*HTTPSListener); ok && profile != nil {
			if p, err := malleableProfileFromPB(profile); err == nil {
				hl.SetMalleableProfile(p)
			}
		}
	}
	return nil
}

func (m *Manager) applyStoredProfile(lis Listener) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hl, ok := lis.(*HTTPSListener)
	if !ok {
		return
	}
	pbProf, ok := m.profiles[lis.ID()]
	if !ok || pbProf == nil {
		return
	}
	if p, err := malleableProfileFromPB(pbProf); err == nil {
		hl.SetMalleableProfile(p)
	}
}

func (m *Manager) GetActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.listeners)
}

// SetTunnelManager attaches a TunnelManager for HTTPS listeners to use
func (m *Manager) SetTunnelManager(tm TunnelManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnels = tm

	for _, lis := range m.listeners {
		if hl, ok := lis.(*HTTPSListener); ok {
			hl.SetTunnelManager(tm)
		}
	}
}
