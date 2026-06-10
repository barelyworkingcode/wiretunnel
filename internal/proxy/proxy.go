// Package proxy bridges the WireGuard network to services reachable from the
// host's normal network. For each forwarding rule it listens on the WireGuard
// netstack and relays accepted connections to the configured target using the
// host's ordinary network stack — making the tunnel a userspace beachhead.
//
// An optional catch-all (StartWildcard) installs a gVisor transport forwarder so
// any tunnel port without an explicit listener is proxied to the same port on a
// default target. Explicit forwards always win, because the stack only routes a
// packet to the forwarder when no bound endpoint matches it.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/barelyworkingcode/wiretunnel/internal/rules"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	dialTimeout = 10 * time.Second
	// udpIdle is how long a UDP session waits for target traffic before it is
	// torn down. UDP is connectionless, so sessions are reaped on idleness.
	udpIdle = 60 * time.Second
	// udpBufSize bounds a single UDP datagram read.
	udpBufSize = 64 * 1024
	// wildMaxInFlight caps half-open TCP handshakes the wildcard forwarder will
	// track at once; excess SYNs are dropped (the client retransmits).
	wildMaxInFlight = 1024
)

// Proxy runs the forwarding listeners for one tunnel.
type Proxy struct {
	net    *netstack.Net
	dialer *net.Dialer
	log    *slog.Logger
	wg     sync.WaitGroup

	stats []*forwardStat // one per explicit forward, in rule order; read via Snapshot

	mu        sync.Mutex
	closing   bool
	listeners []io.Closer       // listeners + relays, closed on shutdown
	conns     map[net.Conn]bool // in-flight inbound conns, closed on shutdown

	// Wildcard (catch-all) forwarding. wildTarget is the host every unmatched
	// tunnel port is proxied to (on the same port); wild holds the per-port stats
	// discovered at runtime. Both are zero/nil unless StartWildcard ran.
	wildTarget string
	muWild     sync.Mutex
	wild       map[string]*forwardStat // key "tcp:8080" / "udp:53"
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
				p.forwardTCP(ctx, conn, st)
			}()
		}
	}()
	return nil
}

// forwardTCP dials the stat's target on the host network and relays the inbound
// tunnel connection to it. It serves both explicit forwards and wildcard ones —
// the only difference is how st (and its target) was created.
func (p *Proxy) forwardTCP(ctx context.Context, in net.Conn, st *forwardStat) {
	defer in.Close()

	st.active.Add(1)
	st.total.Add(1)
	defer st.active.Add(-1)

	out, err := p.dialer.DialContext(ctx, "tcp", st.target)
	if err != nil {
		p.log.Warn("dial target failed", "proto", "tcp", "target", st.target, "remote", in.RemoteAddr(), "err", err)
		return
	}
	defer out.Close()

	p.log.Debug("tcp connection open", "tunnelPort", st.listen, "target", st.target, "remote", in.RemoteAddr())
	pipe(in, out, &st.bytesUp, &st.bytesDown)
	p.log.Debug("tcp connection closed", "tunnelPort", st.listen, "target", st.target, "remote", in.RemoteAddr())
}

// pipe copies bytes in both directions between a and b. When one direction
// reaches EOF it half-closes the destination's write side (CloseWrite) so the
// peer sees the FIN while the opposite direction keeps draining; only once both
// directions have finished are both ends fully closed. This preserves data still
// in flight on the other half — a plain "close both on first EOF" can truncate a
// bulk transfer whose far side has stopped sending but not finished receiving.
// Bytes a->b are counted into aToB and b->a into bToA. It blocks for the whole
// connection lifetime, so callers can rely on it as such.
func pipe(a, b net.Conn, aToB, bToA *atomic.Int64) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn, n *atomic.Int64) {
		_, _ = io.Copy(countWriter{dst, n}, src)
		// Half-close: signal EOF downstream but let the other direction keep
		// draining. Both gonet (netstack) conns and *net.TCPConn implement
		// CloseWrite; fall back to a full close only if some type doesn't.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(b, a, aToB) // a -> b
	go cp(a, b, bToA) // b -> a
	<-done
	<-done
	// Both directions have ended — release both endpoints fully.
	a.Close()
	b.Close()
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

// --- wildcard (catch-all) forwarding ---

// StartWildcard installs a catch-all forwarder: any tunnel TCP or UDP port that
// has no explicit listener is proxied to target on the same port. Explicit
// forwards registered via Start take precedence — gVisor only routes a packet to
// this handler when no bound endpoint matches it.
//
// It registers a stack-wide default handler, which must be done before the
// WireGuard device is brought up (i.e. before any packet is processed), so that
// the unsynchronized handler install has a happens-before relationship with the
// reads on the packet path. Call it after Start but before tunnel bring-up.
func (p *Proxy) StartWildcard(ctx context.Context, target string) error {
	s := stackOf(p.net)
	if s == nil {
		return fmt.Errorf("wildcard forwarding: could not access netstack")
	}
	p.wildTarget = target
	p.wild = make(map[string]*forwardStat)

	tcpFwd := tcp.NewForwarder(s, 0, wildMaxInFlight, func(req *tcp.ForwarderRequest) {
		p.handleWildcardTCP(ctx, req)
	})
	udpFwd := udp.NewForwarder(s, func(req *udp.ForwarderRequest) {
		p.handleWildcardUDP(ctx, req)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	p.log.Info("forwarding", "proto", "tcp+udp", "tunnelPort", "*", "target", target)
	return nil
}

// handleWildcardTCP completes the handshake for a catch-all TCP connection and
// relays it to <wildTarget>:<requested port>.
func (p *Proxy) handleWildcardTCP(ctx context.Context, req *tcp.ForwarderRequest) {
	port := int(req.ID().LocalPort)
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		p.log.Warn("wildcard tcp accept failed", "tunnelPort", port, "err", terr.String())
		req.Complete(true) // send RST
		return
	}
	req.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	if !p.trackConn(conn) {
		conn.Close()
		return // already shutting down
	}
	st := p.wildStat("tcp", port)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer p.untrackConn(conn)
		p.forwardTCP(ctx, conn, st)
	}()
}

// handleWildcardUDP creates a per-flow endpoint for a catch-all UDP session and
// relays it to <wildTarget>:<requested port>. CreateEndpoint registers the
// 4-tuple, so subsequent datagrams from the same client bypass this handler.
func (p *Proxy) handleWildcardUDP(ctx context.Context, req *udp.ForwarderRequest) {
	port := int(req.ID().LocalPort)
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		p.log.Warn("wildcard udp accept failed", "tunnelPort", port, "err", terr.String())
		return
	}

	conn := gonet.NewUDPConn(&wq, ep)
	if !p.trackConn(conn) {
		conn.Close()
		return // already shutting down
	}
	st := p.wildStat("udp", port)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer p.untrackConn(conn)
		p.forwardWildcardUDP(ctx, conn, st)
	}()
}

// forwardWildcardUDP dials the stat's target and relays datagrams in both
// directions until either side idles out. Unlike the explicit UDP relay, the
// inbound side is already a per-client connected endpoint, so a plain
// bidirectional copy suffices.
func (p *Proxy) forwardWildcardUDP(ctx context.Context, in net.Conn, st *forwardStat) {
	defer in.Close()

	st.active.Add(1)
	st.total.Add(1)
	defer st.active.Add(-1)

	out, err := p.dialer.DialContext(ctx, "udp", st.target)
	if err != nil {
		p.log.Warn("dial target failed", "proto", "udp", "target", st.target, "remote", in.RemoteAddr(), "err", err)
		return
	}
	defer out.Close()

	p.log.Debug("udp session open", "tunnelPort", st.listen, "target", st.target, "remote", in.RemoteAddr())
	pipeUDP(in, out, &st.bytesUp, &st.bytesDown)
	p.log.Debug("udp session closed", "tunnelPort", st.listen, "target", st.target, "remote", in.RemoteAddr())
}

// pipeUDP copies datagrams both ways between a and b, counting a->b into aToB and
// b->a into bToA. Each Read carries one datagram, so boundaries are preserved. A
// read deadline reaps the session once both directions have been idle for udpIdle.
func pipeUDP(a, b net.Conn, aToB, bToA *atomic.Int64) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn, n *atomic.Int64) {
		buf := make([]byte, udpBufSize)
		for {
			_ = src.SetReadDeadline(time.Now().Add(udpIdle))
			m, err := src.Read(buf)
			if m > 0 {
				if _, werr := dst.Write(buf[:m]); werr != nil {
					break
				}
				n.Add(int64(m))
			}
			if err != nil {
				break
			}
		}
		a.Close()
		b.Close()
		done <- struct{}{}
	}
	go cp(b, a, aToB) // a -> b
	go cp(a, b, bToA) // b -> a
	<-done
	<-done
}

// wildStat returns the live counters for a wildcard (proto, port), creating them
// on first use. The target is <wildTarget>:<port>, matching the catch-all rule.
func (p *Proxy) wildStat(proto string, port int) *forwardStat {
	key := proto + ":" + strconv.Itoa(port)
	p.muWild.Lock()
	defer p.muWild.Unlock()
	if st, ok := p.wild[key]; ok {
		return st
	}
	st := &forwardStat{
		listen:   port,
		proto:    proto,
		target:   net.JoinHostPort(p.wildTarget, strconv.Itoa(port)),
		wildcard: true,
	}
	p.wild[key] = st
	return st
}

// Wildcard reports the catch-all target and whether it is enabled.
func (p *Proxy) Wildcard() (target string, enabled bool) {
	return p.wildTarget, p.wild != nil
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
	if out, ok := r.sessions[key]; ok {
		r.mu.Unlock()
		return out
	}
	r.mu.Unlock()

	// Dial outside the lock: DialContext may resolve DNS, and holding r.mu
	// across it would stall every other session's teardown, the stats Snapshot,
	// and shutdown for as long as the lookup takes.
	out, err := r.dialer.DialContext(ctx, "udp", r.target)
	if err != nil {
		r.log.Warn("udp dial target failed", "target", r.target, "err", err)
		return nil
	}

	r.mu.Lock()
	if existing, ok := r.sessions[key]; ok {
		// Lost a race for this source — keep the first session, drop ours.
		r.mu.Unlock()
		out.Close()
		return existing
	}
	r.sessions[key] = out
	r.mu.Unlock()

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
