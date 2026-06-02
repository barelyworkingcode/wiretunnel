package proxy

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestPipeBidirectional verifies pipe relays bytes in both directions between
// two connections, counts bytes per direction, and tears the bridge down when
// either side closes.
func TestPipeBidirectional(t *testing.T) {
	// client <-> proxyA   and   proxyB <-> target, bridged by pipe(proxyA, proxyB).
	client, proxyA := net.Pipe()
	proxyB, target := net.Pipe()

	var up, down atomic.Int64 // up = proxyA->proxyB (client->target), down = reverse
	done := make(chan struct{})
	go func() {
		pipe(proxyA, proxyB, &up, &down)
		close(done)
	}()

	upMsg := []byte("ping over the tunnel")
	downMsg := []byte("pong back through")
	assertRelay(t, client, target, upMsg)   // client -> target
	assertRelay(t, target, client, downMsg) // target -> client

	// Closing the client must unblock and end the pipe.
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe did not return after client close")
	}
	target.Close()

	if got := up.Load(); got != int64(len(upMsg)) {
		t.Errorf("up bytes = %d, want %d", got, len(upMsg))
	}
	if got := down.Load(); got != int64(len(downMsg)) {
		t.Errorf("down bytes = %d, want %d", got, len(downMsg))
	}
}

func assertRelay(t *testing.T, from, to net.Conn, msg []byte) {
	t.Helper()
	from.SetDeadline(time.Now().Add(2 * time.Second))
	to.SetDeadline(time.Now().Add(2 * time.Second))

	errc := make(chan error, 1)
	go func() {
		_, err := from.Write(msg)
		errc <- err
	}()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(to, buf); err != nil {
		t.Fatalf("read relayed bytes: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("relayed %q, want %q", buf, msg)
	}
}
