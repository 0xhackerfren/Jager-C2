package events

import (
	"sync"
	"testing"
	"time"
)

func TestNewBus(t *testing.T) {
	bus := NewBus()
	if bus == nil {
		t.Fatal("expected non-nil bus")
	}
}

func TestSubscribeReceivesEvents(t *testing.T) {
	bus := NewBus()
	ch := bus.Subscribe()
	defer bus.Unsubscribe(ch)

	bus.Publish(Event{
		Type:      EventSessionNew,
		SessionID: "sess-1",
	})

	select {
	case e := <-ch:
		if e.Type != EventSessionNew {
			t.Fatalf("expected event type %s, got %s", EventSessionNew, e.Type)
		}
		if e.SessionID != "sess-1" {
			t.Fatalf("expected session_id 'sess-1', got '%s'", e.SessionID)
		}
		if e.Timestamp.IsZero() {
			t.Fatal("timestamp should be set by Publish")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestMultipleSubscribers(t *testing.T) {
	bus := NewBus()
	ch1 := bus.Subscribe()
	ch2 := bus.Subscribe()
	defer bus.Unsubscribe(ch1)
	defer bus.Unsubscribe(ch2)

	bus.Publish(Event{Type: EventTaskQueued, TaskID: "task-1"})

	for _, ch := range []chan Event{ch1, ch2} {
		select {
		case e := <-ch:
			if e.TaskID != "task-1" {
				t.Fatalf("expected task_id 'task-1', got '%s'", e.TaskID)
			}
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive event")
		}
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	bus := NewBus()
	ch := bus.Subscribe()

	bus.Publish(Event{Type: EventCredFound})
	<-ch

	bus.Unsubscribe(ch)

	bus.Publish(Event{Type: EventBuildComplete})

	// Channel should be closed; reading should give zero value
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to be closed after unsubscribe")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("channel not closed after unsubscribe")
	}
}

func TestPublishSetsTimestamp(t *testing.T) {
	bus := NewBus()
	ch := bus.Subscribe()
	defer bus.Unsubscribe(ch)

	before := time.Now()
	bus.Publish(Event{Type: EventListenerStart})
	after := time.Now()

	e := <-ch
	if e.Timestamp.Before(before) || e.Timestamp.After(after) {
		t.Fatal("timestamp should be between before and after publish")
	}
}

func TestPublishOnNilBus(t *testing.T) {
	var bus *Bus
	// Should not panic
	bus.Publish(Event{Type: EventSessionDead})
}

func TestSlowSubscriberDropsEvents(t *testing.T) {
	bus := NewBus()
	ch := bus.Subscribe()
	defer bus.Unsubscribe(ch)

	// Fill the buffer (100 capacity)
	for i := 0; i < 150; i++ {
		bus.Publish(Event{Type: EventTaskSent, TaskID: "overflow"})
	}

	// Should not deadlock; at most 100 events received
	count := 0
	for {
		select {
		case <-ch:
			count++
		default:
			goto done
		}
	}
done:
	if count > 100 {
		t.Fatalf("channel capacity is 100 but received %d", count)
	}
	if count < 100 {
		t.Fatalf("expected at least 100 buffered events, got %d", count)
	}
}

func TestConcurrentPublish(t *testing.T) {
	bus := NewBus()
	ch := bus.Subscribe()
	defer bus.Unsubscribe(ch)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				bus.Publish(Event{Type: EventTaskCompleted})
			}
		}()
	}

	wg.Wait()

	count := 0
	for {
		select {
		case <-ch:
			count++
		default:
			goto done2
		}
	}
done2:
	if count != 100 {
		t.Fatalf("expected 100 events from 10 goroutines * 10, got %d", count)
	}
}

func TestConcurrentSubscribeUnsubscribe(t *testing.T) {
	bus := NewBus()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch := bus.Subscribe()
			bus.Publish(Event{Type: EventSessionCheckin})
			time.Sleep(10 * time.Millisecond)
			bus.Unsubscribe(ch)
		}()
	}

	wg.Wait()
}
