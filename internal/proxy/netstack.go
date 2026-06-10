package proxy

import (
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// netTunPrefix mirrors the leading fields of wireguard-go's unexported
// netstack.netTun so we can reach the embedded *stack.Stack. The library exposes
// only Dial/Listen helpers, but a catch-all forwarder — which serves every tunnel
// port that has no dedicated listener — can only be registered on the gVisor
// stack itself (stack.SetTransportProtocolHandler).
//
// This is a layout pun, not a supported API, so it is deliberately narrow: only
// the two fields up to and including stack must match. The wireguard dependency
// is pinned in go.mod, so the layout cannot drift without a deliberate bump, and
// TestStackOf fails loudly if it ever does.
type netTunPrefix struct {
	ep    *channel.Endpoint
	stack *stack.Stack
}

// stackOf returns the gVisor stack backing a wireguard-go netstack.Net.
func stackOf(n *netstack.Net) *stack.Stack {
	return (*netTunPrefix)(unsafe.Pointer(n)).stack
}
