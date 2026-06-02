package proxy

import (
	"io"
	"sync/atomic"
)

// forwardStat holds live counters for one forwarding rule. Every counter is
// atomic so the data path never blocks on the metrics reader.
type forwardStat struct {
	listen int
	proto  string
	target string

	active    atomic.Int64 // currently open connections / UDP sessions
	total     atomic.Int64 // cumulative connections / UDP sessions
	bytesUp   atomic.Int64 // tunnel client -> target
	bytesDown atomic.Int64 // target -> tunnel client
}

// ForwardSnapshot is an immutable copy of one forward's counters at an instant.
type ForwardSnapshot struct {
	Listen    int
	Proto     string
	Target    string
	Active    int64
	Total     int64
	BytesUp   int64
	BytesDown int64
}

// Snapshot returns the current counters for every forward, in rule order. It is
// safe to call concurrently with active traffic.
func (p *Proxy) Snapshot() []ForwardSnapshot {
	out := make([]ForwardSnapshot, len(p.stats))
	for i, s := range p.stats {
		out[i] = ForwardSnapshot{
			Listen:    s.listen,
			Proto:     s.proto,
			Target:    s.target,
			Active:    s.active.Load(),
			Total:     s.total.Load(),
			BytesUp:   s.bytesUp.Load(),
			BytesDown: s.bytesDown.Load(),
		}
	}
	return out
}

// countWriter adds the number of bytes written through it to n.
type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(p []byte) (int, error) {
	written, err := c.w.Write(p)
	if written > 0 && c.n != nil {
		c.n.Add(int64(written))
	}
	return written, err
}
