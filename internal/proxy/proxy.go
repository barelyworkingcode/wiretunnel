// Package proxy bridges the WireGuard network to services reachable from the
// host's normal network. For each forwarding rule it listens on the WireGuard
// netstack and relays accepted connections to the configured target using the
// host's ordinary network stack — making the tunnel a userspace beachhead.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/barelyworkingcode/wiretunnel/internal/rules"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	dialTimeout = 10 * time.Second
	// udpIdle is how long a UDP session waits for target traffic before it is
	// torn down. UDP is connectionless, so sessions are reaped on idleness.
	udpIdle = 60 * time.Second
	// udpBufSize bounds a single UDP datagram read.
	udpBufSize = 64 * 1024
)

// Proxy runs the forwarding listeners for one tunnel.
type Proxy struct {
	net    *netstack.Net
	dialer *net.Dialer
	log    *slog.Logger
	wg     sync.WaitGroup

	stats []*forwardStat // one per forward, in rule order; read via Snapshot

	mu        sync.Mutex
	closing   bool
	listeners []io.Closer       // listeners + relays, closed on shutdown
	conns     map[net.Conn]bool // in-flight inbound conns, closed on shutdown
}

// New creates a proxy that listens on tnet (the WireGuard side) and dials
// targets via the host network.
func New(tnet *netstack.Net, log *slog.Logger) *Proxy {
	return &Proxy{
		net:    tnet,
		dialer: &net.Dialer{Timeout: dialTimeout},
		log:    log,
		conns:  make(map[net.Conn]bool),
	}
}

// Start binds a listener for every forward and begins serving in the
// background. It returns an error if any listener fails to bind. Listeners and
// in-flight connections run until ctx is cancelled, at which point they are
// closed; call Wait to block until everything has drained.
func (p *Proxy) Start(ctx context.Context, fwds []rules.Forward) error {
	for _, f := range fwds {
		st := &forwardStat{listen: f.Listen, proto: string(f.Proto), target: f.TargetAddr()}
		p.stats = append(p.stats, st)

		var err error
		switch f.Proto {
		case rules.TCP:
			err = p.startTCP(ctx, f, st)
		case rules.UDP:
			err = p.startUDP(ctx, f, st)
		default:
			err = fmt.Errorf("forward :%d: unsupported protocol %q", f.Listen, f.Proto)
		}
		if err != nil {
			p.shutdown()
			return err
		}
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		<-ctx.Done()
		p.shutdown()
	}()
	return nil
}

// Wait blocks until all listeners and in-flight connections have finished,
// which happens after the context passed to Start is cancelled.
func (p *Proxy) Wait() {
	p.wg.Wait()
}

func (p *Proxy) startTCP(ctx context.Context, f rules.Forward, st *forwardStat) error {
	ln, err := p.net.ListenTCP(&net.TCPAddr{Port: f.Listen})
	if err != nil {
		return fmt.Errorf("listen tcp/%d on tunnel: %w", f.Listen, err)
	}
	if !p.addListener(ln) {
		ln.Close()
		return nil // already shutting down
	}
	p.log.Info("forwarding", "proto", "tcp", "tunnelPort", f.Listen, "target", f.TargetAddr())

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !p.isClosing() {
					p.log.Error("accept failed", "tunnelPort", f.Listen, "err", err)
				}
				return
			}
			if !p.trackConn(conn) {
				conn.Close()
				continue
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer p.untrackConn(conn)
				p.forwardTCP(ctx, conn, f, st)
			}()
		}
	}()
	return nil
}

func (p *Proxy) forwardTCP(ctx context.Context, in net.Conn, f rules.Forward, st *forwardStat) {
	defer in.Close()

	st.active.Add(1)
	st.total.Add(1)
	defer st.active.Add(-1)

	target := f.TargetAddr()
	out, err := p.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		p.log.Warn("dial target failed", "proto", "tcp", "target", target, "remote", in.RemoteAddr(), "err", err)
		return
	}
	defer out.Close()

	p.log.Debug("tcp connection open", "tunnelPort", f.Listen, "target", target, "remote", in.RemoteAddr())
	pipe(in, out, &st.bytesUp, &st.bytesDown)
	p.log.Debug("tcp connection closed", "tunnelPort", f.Listen, "target", target, "remote", in.RemoteAddr())
}

// pipe copies bytes in both directions between a and b until either direction
// ends, then tears both down. Bytes a->b are counted into aToB and b->a into
// bToA. It blocks until both copy directions finish, so callers can rely on it
// for connection lifetime.
func pipe(a, b net.Conn, aToB, bToA *atomic.Int64) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn, n *atomic.Int64) {
		_, _ = io.Copy(countWriter{dst, n}, src)
		// Closing both ends unblocks the opposite copy direction.
		a.Close()
		b.Close()
		done <- struct{}{}
	}
	go cp(b, a, aToB) // a -> b
	go cp(a, b, bToA) // b -> a
	<-done
	<-done
}

func (p *Proxy) startUDP(ctx context.Context, f rules.Forward, st *forwardStat) error {
	pc, err := p.net.ListenUDP(&net.UDPAddr{Port: f.Listen})
	if err != nil {
		return fmt.Errorf("listen udp/%d on tunnel: %w", f.Listen, err)
	}
	r := &udpRelay{
		pc:         pc,
		target:     f.TargetAddr(),
		listenPort: f.Listen,
		dialer:     p.dialer,
		log:        p.log,
		stat:       st,
		sessions:   make(map[string]net.Conn),
	}
	// Closing the relay stops the read loop and tears down every session.
	if !p.addListener(closerFunc(r.close)) {
		pc.Close()
		return nil // already shutting down
	}
	p.log.Info("forwarding", "proto", "udp", "tunnelPort", f.Listen, "target", f.TargetAddr())

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		r.run(ctx)
	}()
	return nil
}

// --- shutdown bookkeeping ---

// closerFunc adapts a func to io.Closer.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func (p *Proxy) addListener(c io.Closer) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	p.listeners = append(p.listeners, c)
	return true
}

func (p *Proxy) trackConn(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	p.conns[c] = true
	return true
}

func (p *Proxy) untrackConn(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *Proxy) isClosing() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closing
}

// shutdown closes all listeners and in-flight connections so accept loops and
// relays exit promptly. Closers run outside the lock because a relay's Close
// waits for its session goroutines.
func (p *Proxy) shutdown() {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.closing = true
	listeners := p.listeners
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.listeners = nil
	p.mu.Unlock()

	for _, c := range conns {
		c.Close()
	}
	for _, l := range listeners {
		l.Close()
	}
}

// udpRelay forwards datagrams arriving on a tunnel UDP port to a target,
// keeping one outbound socket per tunnel source address so replies route back
// to the right client.
type udpRelay struct {
	pc         net.PacketConn
	target     string
	listenPort int
	dialer     *net.Dialer
	log        *slog.Logger
	stat       *forwardStat

	mu       sync.Mutex
	sessions map[string]net.Conn
	wg       sync.WaitGroup
}

func (r *udpRelay) run(ctx context.Context) {
	buf := make([]byte, udpBufSize)
	for {
		n, src, err := r.pc.ReadFrom(buf)
		if err != nil {
			return // listener closed
		}
		out := r.session(ctx, src)
		if out == nil {
			continue
		}
		if _, err := out.Write(buf[:n]); err != nil {
			r.log.Warn("udp write to target failed", "target", r.target, "err", err)
			continue
		}
		r.stat.bytesUp.Add(int64(n))
	}
}

// session returns the outbound socket for a tunnel source, creating it (and the
// reply pump) on first use.
func (r *udpRelay) session(ctx context.Context, src net.Addr) net.Conn {
	key := src.String()

	r.mu.Lock()
	defer r.mu.Unlock()
	if out, ok := r.sessions[key]; ok {
		return out
	}

	out, err := r.dialer.DialContext(ctx, "udp", r.target)
	if err != nil {
		r.log.Warn("udp dial target failed", "target", r.target, "err", err)
		return nil
	}
	r.sessions[key] = out
	r.stat.active.Add(1)
	r.stat.total.Add(1)
	r.log.Debug("udp session open", "tunnelPort", r.listenPort, "target", r.target, "remote", src)

	r.wg.Add(1)
	go r.replyLoop(src, key, out)
	return out
}

func (r *udpRelay) replyLoop(src net.Addr, key string, out net.Conn) {
	defer r.wg.Done()
	defer func() {
		r.mu.Lock()
		if r.sessions[key] == out {
			delete(r.sessions, key)
		}
		r.mu.Unlock()
		out.Close()
		r.stat.active.Add(-1)
		r.log.Debug("udp session closed", "tunnelPort", r.listenPort, "target", r.target, "remote", src)
	}()

	buf := make([]byte, udpBufSize)
	for {
		_ = out.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := out.Read(buf)
		if err != nil {
			return
		}
		if _, err := r.pc.WriteTo(buf[:n], src); err != nil {
			return
		}
		r.stat.bytesDown.Add(int64(n))
	}
}

// close stops the read loop and tears down all sessions, blocking until the
// reply goroutines have exited.
func (r *udpRelay) close() error {
	r.pc.Close()
	r.mu.Lock()
	for _, out := range r.sessions {
		out.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
	return nil
}
