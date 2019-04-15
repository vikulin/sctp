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
		ln, err := NewSCTPListener(tt, InitMsg{}, OneToOne, false)
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
	ln, err := NewSCTPListener(addr, InitMsg{}, OneToMany, false)
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
		c, err := NewSCTPConnection(nil, ln.LocalAddr().(*SCTPAddr), InitMsg{}, OneToOne, false)
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
	ln, err := NewSCTPListener(addr, InitMsg{}, OneToOne, false)
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

	_, err = NewSCTPConnection(nil, ln.LocalAddr().(*SCTPAddr), InitMsg{}, OneToOne, false)
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
	ln, err := NewSCTPListener(addr, InitMsg{}, OneToMany, false)
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
		c, err := NewSCTPConnection(nil, ln.LocalAddr().(*SCTPAddr), InitMsg{}, OneToOne, false)
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

func TestOneToManyPeelOff(t *testing.T) {

	const (
		SERVER_ROUTINE_COUNT = 10
		CLIENT_ROUTINE_COUNT = 100
	)
	var wg sync.WaitGroup
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr(SCTP4, "127.0.0.1:0")
	ln, err := NewSCTPListener(addr, InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS}, OneToMany, false)
	if err != nil {
		t.Fatal(err)
	}

	laddr, _ := ln.LocalAddr().(*SCTPAddr)

	ln.Socket.SubscribeEvents(SCTP_EVENT_ASSOCIATION)

	go func() {
		test := 999
		count := 0
		for {
			t.Logf("[%d]Reading from server socket...\n", test)
			buf := make([]byte, 512)
			n, oob, flags, err := ln.SCTPRead(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				t.Fatalf("[%d]Got an error reading from main socket", test)
			}

			if flags&MSG_NOTIFICATION > 0 {
				t.Logf("[%d]Got a notification. Bytes read: %v\n", test, n)
				notif, _ := parseNotification(buf[:n])
				switch notif.Type() {
				case SCTP_ASSOC_CHANGE:
					t.Logf("[%d]Got an association change notification\n", test)
					assocChange := notif.GetAssociationChange()
					if assocChange.State == SCTP_COMM_UP {
						t.Logf("[%d]SCTP_COMM_UP. Creating socket for association: %v\n", test, assocChange.AssocID)
						newSocket, err := ln.Socket.PeelOff(int(assocChange.AssocID))
						if err != nil {
							t.Fatalf("Failed to peel off socket: %v", err)
						}
						t.Logf("[%d]Peeled off socket: %#+v\n", test, newSocket)
						if err := newSocket.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
							t.Logf("[%d]Failed to subscribe to data io for peeled off socket: %v -> %#+v\n", test, err, newSocket)
						}
						count++
						go socketReaderMirror(newSocket, t, test-count)
						continue
					}
				}
			}

			if flags&MSG_EOR > 0 {
				info := oob.GetSndRcvInfo()
				t.Logf("[%d]Got data on main socket, but it wasn't a notification: %#+v \n", test, info)
				wn, werr := ln.SCTPWrite(buf[:n],
					&SndRcvInfo{
						AssocID: info.AssocID,
						Stream:  info.Stream,
						PPID:    info.PPID,
					},
				)
				if werr != nil {
					t.Errorf("[%d]failed to write %s, len: %d, err: %v, bytes written: %d, info: %+v", test, string(buf[:n]), len(buf[:n]), werr, wn, info)
					return
				}
				continue
			}
			t.Logf("[%d]No clue wtf is happening", test)
		}
	}()

	for i := CLIENT_ROUTINE_COUNT; i > 0; i-- {
		wg.Add(1)
		go func(client int, l *SCTPAddr) {
			defer wg.Done()
			t.Logf("[%d]Creating new client connection\n", client)
			c, err := NewSCTPConnection(nil, l, InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS}, OneToOne, false)
			if err != nil {
				t.Fatalf("[%d]Failed to connect to SCTP server: %v", client, err)
			}
			c.SubscribeEvents(SCTP_EVENT_DATA_IO)
			for q := range []int{0, 1} {
				rstring := randomString(10)
				rstream := uint16(r.Intn(STREAM_TEST_STREAMS))
				t.Logf("[%d]Writing to client socket. Data:%v, Stream:%v, MsgCount:%v \n", client, rstring, rstream, q)
				_, err = c.SCTPWrite(
					[]byte(rstring),
					&SndRcvInfo{
						Stream: rstream,
						PPID:   uint32(q),
					},
				)
				if err != nil {
					t.Fatalf("Failed to send data to SCTP server: %v", err)
				}

				t.Logf("[%d]Reading from client socket...\n", client)
				buf := make([]byte, 512)
				n, oob, _, err := c.SCTPRead(buf)
				if err != nil {
					t.Fatalf("Failed to read from client socket: %v", err)
				}
				if oob == nil {
					t.Fatal("WTF. OOB is nil?!")
				}
				t.Logf("[%d]***Read from client socket\n", client)
				if oob.GetSndRcvInfo().Stream != rstream {
					t.Fatalf("Data received on a stream(%v) we didn't send(%v) on",
						oob.GetSndRcvInfo().Stream,
						rstream)
				}
				if string(buf[:n]) != rstring {
					t.Fatalf("Data from server doesn't match what client sent\nSent: %v\nReceived: %v",
						rstring,
						string(buf[:n]),
					)
				}
				t.Logf("[%d]Client read success! MsgCount: %v\n", client, q)
			}
			c.Close()

		}(i, laddr)
	}
	wg.Wait()
	ln.Close()
}

func socketReaderMirror(sock *SCTPConn, t *testing.T, goroutine int) {
	for {
		t.Logf("[%d]Reading peel off server socket...\n", goroutine)
		buf := make([]byte, 512)
		n, oob, flags, err := sock.SCTPRead(buf)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF || err == syscall.ENOTCONN {
				t.Logf("[%d]Got EOF...\n", goroutine)
				sock.Close()
				break
			}
			t.Fatalf("[%d]Failed to read from socket: %#+v", goroutine, err)
		}

		if flags&MSG_NOTIFICATION > 0 {
			t.Logf("[%d]Notification received. Byte count: %v, OOB: %#+v, Flags: %v\n", goroutine, n, oob, flags)
			if notif, err := parseNotification(buf[:n]); err == nil {
				t.Logf("[%d]Notification type: %v\n", goroutine, notif.Type().String())
			}
		}
		t.Logf("[%d]Writing peel off server socket...\n", goroutine)
		info := oob.GetSndRcvInfo()
		wn, werr := sock.SCTPWrite(buf[:n],
			&SndRcvInfo{
				AssocID: info.AssocID,
				Stream:  info.Stream,
				PPID:    info.PPID,
			},
		)
		if werr != nil {
			t.Errorf("[%d]failed to write %s, len: %d, err: %v, bytes written: %d, info: %+v", goroutine, string(buf[:n]), len(buf[:n]), werr, wn, info)
			return
		}
	}
}
