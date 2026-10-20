package pivot

import (
	"testing"
	"time"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"go.uber.org/zap"
)

func TestWaitForFirstFrameAck(t *testing.T) {
	tm := NewTunnelManager(zap.NewNop())
	sid := "sess-1"
	ch := tm.AllocChannel(sid)
	defer tm.FreeChannel(ch)

	go func() {
		time.Sleep(20 * time.Millisecond)
		tm.SendToImplant(sid, &pb.TunnelFrame{
			ChannelID: ch,
			Op:        pb.TunnelOp_DATA,
			SessionID: sid,
		})
	}()

	frame := tm.WaitForFirstFrame(ch, 2*time.Second)
	if frame == nil {
		t.Fatal("expected ack frame")
	}
	if frame.Op != pb.TunnelOp_DATA {
		t.Fatalf("expected DATA ack, got %v", frame.Op)
	}
}

func TestWaitForFirstFrameTimeout(t *testing.T) {
	tm := NewTunnelManager(zap.NewNop())
	ch := tm.AllocChannel("sess-2")
	defer tm.FreeChannel(ch)

	frame := tm.WaitForFirstFrame(ch, 50*time.Millisecond)
	if frame != nil {
		t.Fatal("expected timeout nil frame")
	}
}
