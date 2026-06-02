package main

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// pingProbeTimeout is how long each echo waits for a reply.
const pingProbeTimeout = 2 * time.Second

// pingOverTunnel sends count ICMP echo requests to target across the tunnel,
// originating from the local WireGuard address, and prints the results. It
// returns an error if no reply is received (e.g. the handshake never completed
// or the host is unreachable). This is the connectivity self-test: the tunnel
// address itself is not on any host interface, so it can only be reached over
// the WireGuard network — this exercises that path from the beachhead outward.
func pingOverTunnel(tnet *netstack.Net, local, target netip.Addr, count int) error {
	pc, err := tnet.DialPingAddr(local, target)
	if err != nil {
		return fmt.Errorf("open ping socket: %w", err)
	}
	defer pc.Close()

	echoType, replyType, proto := pingProto(target)
	id := os.Getpid() & 0xffff
	received := 0

	fmt.Printf("PING %s from %s over the tunnel:\n", target, local)
	for seq := 1; seq <= count; seq++ {
		req, err := (&icmp.Message{
			Type: echoType, Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("wiretunnel-probe")},
		}).Marshal(nil)
		if err != nil {
			return fmt.Errorf("marshal echo: %w", err)
		}

		start := time.Now()
		_ = pc.SetReadDeadline(time.Now().Add(pingProbeTimeout))
		if _, err := pc.Write(req); err != nil {
			fmt.Printf("  icmp_seq=%d send failed: %v\n", seq, err)
			continue
		}

		buf := make([]byte, 1500)
		n, err := pc.Read(buf)
		if err != nil {
			fmt.Printf("  icmp_seq=%d request timed out\n", seq)
			if seq < count {
				time.Sleep(time.Second)
			}
			continue
		}
		rtt := time.Since(start)

		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			fmt.Printf("  icmp_seq=%d malformed reply: %v\n", seq, err)
		} else if msg.Type == replyType {
			fmt.Printf("  reply from %s: icmp_seq=%d time=%.2f ms\n", target, seq, float64(rtt.Microseconds())/1000)
			received++
		} else {
			fmt.Printf("  icmp_seq=%d unexpected icmp type %v\n", seq, msg.Type)
		}
		if seq < count {
			time.Sleep(time.Second)
		}
	}

	fmt.Printf("--- %s ping statistics ---\n%d transmitted, %d received\n", target, count, received)
	if received == 0 {
		return fmt.Errorf("no reply from %s over the tunnel", target)
	}
	return nil
}

func pingProto(addr netip.Addr) (echo, reply icmp.Type, proto int) {
	if addr.Is6() {
		return ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, 58 // IANA ICMPv6
	}
	return ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, 1 // IANA ICMPv4
}
