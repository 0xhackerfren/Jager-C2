package events

import (
	"sync"
	"time"
)

type EventType string

const (
	EventSessionNew     EventType = "session.new"
	EventSessionCheckin EventType = "session.checkin"
	EventSessionDead    EventType = "session.dead"
	EventTaskQueued     EventType = "task.queued"
	EventTaskSent       EventType = "task.sent"
	EventTaskCompleted  EventType = "task.completed"
	EventTaskFailed     EventType = "task.failed"
	EventCredFound      EventType = "cred.found"
	EventBuildComplete  EventType = "build.complete"
	EventListenerStart  EventType = "listener.start"
	EventListenerStop   EventType = "listener.stop"
)

type Event struct {
	Type      EventType   `json:"type"`
	Timestamp time.Time   `json:"ts"`
	SessionID string      `json:"session_id,omitempty"`
	TaskID    string      `json:"task_id,omitempty"`
	Data      interface{} `json:"data,omitempty"`
}

type Bus struct {
	mu        sync.RWMutex
	listeners map[chan Event]struct{}
	history   []Event
	maxHist   int
}

func NewBus() *Bus {
	return &Bus{
		listeners: make(map[chan Event]struct{}),
		maxHist:   500,
	}
}

func (b *Bus) Subscribe() chan Event {
	ch := make(chan Event, 100)
	b.mu.Lock()
	b.listeners[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Bus) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	delete(b.listeners, ch)
	b.mu.Unlock()
	close(ch)
}

func (b *Bus) Publish(e Event) {
	if b == nil {
		return
	}
	e.Timestamp = time.Now()
	b.mu.Lock()
	b.history = append(b.history, e)
	if len(b.history) > b.maxHist {
		b.history = b.history[len(b.history)-b.maxHist:]
	}
	b.mu.Unlock()

	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.listeners {
		select {
		case ch <- e:
		default:
		}
	}
}

// Recent returns events from the last `since` duration, optionally filtered by type.
func (b *Bus) Recent(since time.Duration, types []EventType) []Event {
	if b == nil {
		return nil
	}
	cutoff := time.Now().Add(-since)
	typeSet := make(map[EventType]bool, len(types))
	for _, t := range types {
		typeSet[t] = true
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	var result []Event
	for i := len(b.history) - 1; i >= 0; i-- {
		ev := b.history[i]
		if ev.Timestamp.Before(cutoff) {
			break
		}
		if len(typeSet) > 0 && !typeSet[ev.Type] {
			continue
		}
		result = append(result, ev)
	}

	// Reverse to chronological order
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}
