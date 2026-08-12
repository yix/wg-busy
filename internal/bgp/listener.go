package bgp

import (
	"fmt"
	"net"
	"sync"

	btcp "github.com/bio-routing/bio-rd/net/tcp"
	"github.com/bio-routing/bio-rd/routingtable/vrf"
	"golang.org/x/sys/unix"
)

// listenerManager supplies bio-rd with listeners that wg-busy can actually
// close. bio-rd's built-in ListenerManager has no shutdown API.
type listenerManager struct {
	addresses map[string][]string
	listeners map[string][]*managedListener
	acceptCh  chan btcp.ConnWithVRF
	closed    chan struct{}
	mu        sync.Mutex
	once      sync.Once
}

func newListenerManager(addresses map[string][]string) *listenerManager {
	return &listenerManager{
		addresses: addresses,
		listeners: make(map[string][]*managedListener),
		acceptCh:  make(chan btcp.ConnWithVRF),
		closed:    make(chan struct{}),
	}
}

func (m *listenerManager) ListenAddrsPerVRF(v *vrf.VRF) []string {
	return m.addresses[v.Name()]
}

func (m *listenerManager) GetListeners(v *vrf.VRF) []btcp.ListenerI {
	m.mu.Lock()
	defer m.mu.Unlock()
	listeners := m.listeners[v.Name()]
	result := make([]btcp.ListenerI, len(listeners))
	for i := range listeners {
		result[i] = listeners[i]
	}
	return result
}

func (m *listenerManager) CreateListenersIfNotExists(v *vrf.VRF) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.listeners[v.Name()]; exists {
		return nil
	}

	var created []*managedListener
	for _, address := range m.addresses[v.Name()] {
		tcpAddress, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			closeListeners(created)
			return fmt.Errorf("resolve BGP listener %q: %w", address, err)
		}
		listener, err := net.ListenTCP("tcp", tcpAddress)
		if err != nil {
			closeListeners(created)
			return fmt.Errorf("listen for BGP on %q: %w", address, err)
		}
		managed := &managedListener{TCPListener: listener, ttl: 255}
		created = append(created, managed)
		go m.accept(v, managed)
	}
	m.listeners[v.Name()] = created
	return nil
}

func (m *listenerManager) AcceptCh() chan btcp.ConnWithVRF { return m.acceptCh }

func (m *listenerManager) accept(v *vrf.VRF, listener *managedListener) {
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		select {
		case m.acceptCh <- btcp.ConnWithVRF{Conn: conn, VRF: v}:
		case <-m.closed:
			_ = conn.Close()
			return
		}
	}
}

func (m *listenerManager) Close() error {
	var closeErr error
	m.once.Do(func() {
		close(m.closed)
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, listeners := range m.listeners {
			for _, listener := range listeners {
				if err := listener.Close(); err != nil {
					closeErr = err
				}
			}
		}
		m.listeners = make(map[string][]*managedListener)
	})
	return closeErr
}

func closeListeners(listeners []*managedListener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
}

type managedListener struct {
	*net.TCPListener
	ttl uint8
}

func (l *managedListener) SetTCPMD5(_ net.IP, secret string) error {
	if secret != "" {
		return fmt.Errorf("TCP MD5 is not supported by the managed listener")
	}
	return nil
}

func (l *managedListener) AcceptTCP() (btcp.ConnI, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetNoDelay(true)
	return &managedConn{TCPConn: conn, ttl: l.ttl}, nil
}

// managedConn implements bio-rd's extended ConnI while retaining Go's
// closeable TCP connection. TTL is applied before the first write.
type managedConn struct {
	*net.TCPConn
	ttl     uint8
	ttlOnce sync.Once
	ttlErr  error
}

func (c *managedConn) Write(p []byte) (int, error) {
	c.ttlOnce.Do(func() { c.ttlErr = c.SetTTL(c.ttl) })
	if c.ttlErr != nil {
		return 0, c.ttlErr
	}
	return c.TCPConn.Write(p)
}

func (c *managedConn) SetTTL(ttl uint8) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = raw.Control(func(fd uintptr) {
		level, option := unix.IPPROTO_IP, unix.IP_TTL
		if address, ok := c.RemoteAddr().(*net.TCPAddr); ok && address.IP.To4() == nil {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
		}
		setErr = unix.SetsockoptInt(int(fd), level, option, int(ttl))
	})
	if err != nil {
		return err
	}
	return setErr
}

func (c *managedConn) SetDontRoute() error { return nil }
func (c *managedConn) SetNoDelay() error   { return c.TCPConn.SetNoDelay(true) }
func (c *managedConn) SetBindToDev(string) error {
	return nil
}

var _ btcp.ListenerManagerI = (*listenerManager)(nil)
var _ btcp.ListenerI = (*managedListener)(nil)
var _ btcp.ConnI = (*managedConn)(nil)
