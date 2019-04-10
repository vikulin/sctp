package sctp

import (
	"io"
	"net"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

type resolveSCTPAddrTest struct {
	network       SCTPAddressFamily
	litAddrOrName string
	addr          *SCTPAddr
	err           error
}

var ipv4loop = net.IPv4(127, 0, 0, 1)

var resolveSCTPAddrTests = []resolveSCTPAddrTest{
	{SCTP4, "127.0.0.1:0", &SCTPAddr{AddressFamily: SCTP4, IPAddrs: []net.IPAddr{net.IPAddr{IP: ipv4loop}}, Port: 0}, nil},
	{SCTP4, "127.0.0.1:65535", &SCTPAddr{AddressFamily: SCTP4, IPAddrs: []net.IPAddr{net.IPAddr{IP: ipv4loop}}, Port: 65535}, nil},

	{SCTP6, "[::1]:0", &SCTPAddr{AddressFamily: SCTP6, IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("::1")}}, Port: 0}, nil},
	{SCTP6, "[::1]:65535", &SCTPAddr{AddressFamily: SCTP6, IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("::1")}}, Port: 65535}, nil},

	{SCTP6, "[::1%lo0]:0", &SCTPAddr{AddressFamily: SCTP6, IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("::1"), Zone: "lo0"}}, Port: 0}, nil},
	{SCTP6, "[::1%lo0]:65535", &SCTPAddr{AddressFamily: SCTP6, IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("::1"), Zone: "lo0"}}, Port: 65535}, nil},
	{SCTP4, "0.0.0.0:12345", &SCTPAddr{AddressFamily: SCTP4, IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4zero, Zone: ""}}, Port: 12345}, nil},
	{SCTP4, "127.0.0.1/10.0.0.1:0", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}}, Port: 0}, nil},
	{SCTP4, "127.0.0.1/10.0.0.1:65535", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}}, Port: 65535}, nil},
	{SCTP6, "::1%lo0/127.0.0.1:1234", &SCTPAddr{AddressFamily: SCTP6, IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("::1"), Zone: "lo0"}, net.IPAddr{IP: ipv4loop, Zone: ""}}, Port: 1234}, nil},
}

func TestSCTPAddrString(t *testing.T) {
	for _, tt := range resolveSCTPAddrTests {
		s := tt.addr.String()
		if tt.litAddrOrName != s {
			t.Errorf("expected %q, got %q", tt.litAddrOrName, s)
		}
	}
}

func TestResolveSCTPAddr(t *testing.T) {
	for _, tt := range resolveSCTPAddrTests {
		addr, err := ResolveSCTPAddr(tt.network, tt.litAddrOrName)
		if !reflect.DeepEqual(addr, tt.addr) || !reflect.DeepEqual(err, tt.err) {
			t.Errorf("ResolveSCTPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr, err, tt.addr, tt.err)
			continue
		}
		if err == nil {
			addr2, err := ResolveSCTPAddr(addr.AddressFamily, addr.String())
			if !reflect.DeepEqual(addr2, tt.addr) || err != tt.err {
				t.Errorf("(%q, %q): ResolveSCTPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr.Network(), addr.String(), addr2, err, tt.addr, tt.err)
			}
		}
	}
}

var sctpListenerNameTests = []*SCTPAddr{
	&SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}}},
	&SCTPAddr{},
	nil,
	&SCTPAddr{Port: 7777},
}

func TestSCTPListenerName(t *testing.T) {
	for _, tt := range sctpListenerNameTests {
		ln, err := NewSCTPListener(tt, InitMsg{}, OneToOne)
		if err != nil {
			if tt == nil {
				continue
			}
			t.Fatal(err)
		}
		defer ln.Close()
		la := ln.LocalAddr()
		if a, ok := la.(*SCTPAddr); !ok || a.Port == 0 {
			t.Fatalf("got %v; expected a proper address with non-zero port number", la)
		}
	}
}

func TestSCTPConcurrentAccept(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr(SCTP4, "127.0.0.1:0")
	ln, err := NewSCTPListener(addr, InitMsg{}, OneToMany)
	if err != nil {
		t.Fatal(err)
	}
	const N = 10
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					break
				}
				c.Close()
			}
			wg.Done()
		}()
	}
	attempts := 10 * N
	fails := 0
	for i := 0; i < attempts; i++ {
		c, err := NewSCTPConnection(nil, ln.LocalAddr().(*SCTPAddr), InitMsg{}, OneToOne)
		if err != nil {
			fails++
		} else {
			c.Close()
		}
	}
	ln.Close()
	// BUG Accept() doesn't return even if we closed ln
	//	wg.Wait()
	if fails > 0 {
		t.Fatalf("# of failed Dials: %v", fails)
	}
}

func TestSCTPCloseRecv(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr(SCTP4, "127.0.0.1:0")
	ln, err := NewSCTPListener(addr, InitMsg{}, OneToOne)
	if err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	var wg sync.WaitGroup
	connReady := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var xerr error
		conn, xerr = ln.Accept()
		if xerr != nil {
			t.Fatal(xerr)
		}
		connReady <- struct{}{}
		buf := make([]byte, 256)
		_, xerr = conn.Read(buf)
		t.Logf("got error while read: %v", xerr)
		if xerr != io.EOF && xerr != syscall.EBADF {
			t.Fatalf("read failed: %v", xerr)
		}
	}()

	_, err = NewSCTPConnection(nil, ln.LocalAddr().(*SCTPAddr), InitMsg{}, OneToOne)
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}

	<-connReady
	err = conn.Close()
	if err != nil {
		t.Fatalf("close failed: %v", err)
	}
	wg.Wait()
}

func TestSCTPConcurrentOneToMany(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr(SCTP4, "127.0.0.1:0")
	ln, err := NewSCTPListener(addr, InitMsg{}, OneToMany)
	if err != nil {
		t.Fatal(err)
	}

	ln.Socket.SubscribeEvents(SCTP_EVENT_DATA_IO | SCTP_EVENT_ASSOCIATION)

	const N = 10
	for i := 0; i < N; i++ {
		go func() {
			for {
				buf := make([]byte, 512)
				n, _, flags, err := ln.SCTPRead(buf)
				if err != nil {
					break
				}

				if flags&MSG_NOTIFICATION > 0 {
					notif, _ := parseNotification(buf[:n])
					switch notif.Type() {
					case SCTP_ASSOC_CHANGE:
						assocChange := notif.GetAssociationChange()
						if assocChange.State == SCTP_COMM_UP {
							ln.SCTPWrite([]byte{0}, &SndRcvInfo{Flags: SCTP_EOF, AssocID: assocChange.AssocID})
						}
					}
				}
			}
		}()
	}
	attempts := 10 * N
	fails := 0
	for i := 0; i < attempts; i++ {
		c, err := NewSCTPConnection(nil, ln.LocalAddr().(*SCTPAddr), InitMsg{}, OneToOne)
		if err != nil {
			fails++
		} else {
			c.Close()
		}
	}
	ln.Close()
	if fails > 0 {
		t.Fatalf("# of failed Dials: %v", fails)
	}
}
