package proxy

import (
	"io"
	"sort"
	"sync/atomic"
)

// forwardStat holds live counters for one forwarding rule. Every counter is
// atomic so the data path never blocks on the metrics reader.
type forwardStat struct {
	listen   int
	proto    string
	target   string
	wildcard bool // discovered via the catch-all rule rather than an explicit forward

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
	Wildcard  bool
	Active    int64
	Total     int64
	BytesUp   int64
	BytesDown int64
}

func snapshotOf(s *forwardStat) ForwardSnapshot {
	return ForwardSnapshot{
		Listen:    s.listen,
		Proto:     s.proto,
		Target:    s.target,
		Wildcard:  s.wildcard,
		Active:    s.active.Load(),
		Total:     s.total.Load(),
		BytesUp:   s.bytesUp.Load(),
		BytesDown: s.bytesDown.Load(),
	}
}

// Snapshot returns the current counters for every forward: explicit forwards
// first in rule order, then any wildcard ports discovered at runtime in a stable
// (proto, port) order so dashboard rows don't jump around. Safe to call
// concurrently with active traffic.
func (p *Proxy) Snapshot() []ForwardSnapshot {
	out := make([]ForwardSnapshot, 0, len(p.stats))
	for _, s := range p.stats {
		out = append(out, snapshotOf(s))
	}

	p.muWild.Lock()
	wild := make([]*forwardStat, 0, len(p.wild))
	for _, s := range p.wild {
		wild = append(wild, s)
	}
	p.muWild.Unlock()

	sort.Slice(wild, func(i, j int) bool {
		if wild[i].proto != wild[j].proto {
			return wild[i].proto < wild[j].proto
		}
		return wild[i].listen < wild[j].listen
	})
	for _, s := range wild {
		out = append(out, snapshotOf(s))
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
