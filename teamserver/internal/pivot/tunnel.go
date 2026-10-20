// Package pivot implements teamserver-side SOCKS relay, reverse port
// forwarding, and the TunnelManager that multiplexes data frames over
// the C2 channel to implants.
package pivot

import (
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
)

// TunnelManager tracks open tunnel channels between operator sockets
// and implant sessions. Each channel has a uint32 ID and bidirectional
// frame queues. The HTTPS listener's /api/v1/tunnel endpoint calls
// SendToImplant/GetPendingFrames during implant polls.
type TunnelManager struct {
	mu       sync.Mutex
	nextCh   uint32
	// toImplant: frames queued for delivery to a specific implant session
	toImplant map[string][]*pb.TunnelFrame
	// fromImplant: frames received from implant, keyed by channel_id
	fromImplant map[uint32]chan *pb.TunnelFrame
	// channelSession: maps channel_id -> session_id for routing
	channelSession map[uint32]string
	logger         *zap.Logger
}

func NewTunnelManager(logger *zap.Logger) *TunnelManager {
	return &TunnelManager{
		toImplant:      make(map[string][]*pb.TunnelFrame),
		fromImplant:    make(map[uint32]chan *pb.TunnelFrame),
		channelSession: make(map[uint32]string),
		logger:         logger.Named("tunnel"),
	}
}

// AllocChannel assigns a new channel ID for a tunnel to a specific session
func (tm *TunnelManager) AllocChannel(sessionID string) uint32 {
	id := atomic.AddUint32(&tm.nextCh, 1)
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.channelSession[id] = sessionID
	tm.fromImplant[id] = make(chan *pb.TunnelFrame, 256)
	return id
}

// FreeChannel removes a channel
func (tm *TunnelManager) FreeChannel(channelID uint32) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if ch, ok := tm.fromImplant[channelID]; ok {
		close(ch)
		delete(tm.fromImplant, channelID)
	}
	delete(tm.channelSession, channelID)
}

// QueueToImplant queues a frame for delivery to the implant on next poll
func (tm *TunnelManager) QueueToImplant(sessionID string, frame *pb.TunnelFrame) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.toImplant[sessionID] = append(tm.toImplant[sessionID], frame)
}

// SendToImplant is called by the HTTPS listener when the implant sends
// frames from its side (response data from remote connections)
func (tm *TunnelManager) SendToImplant(sessionID string, frame *pb.TunnelFrame) error {
	tm.mu.Lock()
	ch, ok := tm.fromImplant[frame.ChannelID]
	tm.mu.Unlock()

	if !ok {
		return nil
	}

	select {
	case ch <- frame:
	default:
		tm.logger.Warn("tunnel frame dropped (buffer full)",
			zap.Uint32("channel", frame.ChannelID))
	}
	return nil
}

// GetPendingFrames returns all frames queued for delivery to the implant
// and clears the queue. Called by the HTTPS listener on tunnel poll.
func (tm *TunnelManager) GetPendingFrames(sessionID string) []*pb.TunnelFrame {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	frames := tm.toImplant[sessionID]
	if len(frames) > 0 {
		tm.toImplant[sessionID] = nil
	}
	return frames
}

// ReceiveFromImplant reads a frame from the implant for a specific channel.
// Returns nil if the channel is closed.
func (tm *TunnelManager) ReceiveFromImplant(channelID uint32) *pb.TunnelFrame {
	tm.mu.Lock()
	ch, ok := tm.fromImplant[channelID]
	tm.mu.Unlock()

	if !ok {
		return nil
	}

	frame, ok := <-ch
	if !ok {
		return nil
	}
	return frame
}

// WaitForFirstFrame blocks until the implant sends the first frame on a channel
// (OPEN ack as empty DATA, failure as CLOSE) or timeout expires.
func (tm *TunnelManager) WaitForFirstFrame(channelID uint32, timeout time.Duration) *pb.TunnelFrame {
	tm.mu.Lock()
	ch, ok := tm.fromImplant[channelID]
	tm.mu.Unlock()
	if !ok {
		return nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case frame, open := <-ch:
		if !open {
			return nil
		}
		return frame
	case <-timer.C:
		return nil
	}
}

// HasActiveChannels returns true if there are active tunnel channels
// for the given session
func (tm *TunnelManager) HasActiveChannels(sessionID string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for _, sid := range tm.channelSession {
		if sid == sessionID {
			return true
		}
	}
	return false
}

// ListChannels returns all active channel IDs for a session
func (tm *TunnelManager) ListChannels(sessionID string) []uint32 {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	var ids []uint32
	for id, sid := range tm.channelSession {
		if sid == sessionID {
			ids = append(ids, id)
		}
	}
	return ids
}
