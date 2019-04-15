package sctp

import (
	"fmt"
	syscall "golang.org/x/sys/unix"
	"net"
	"sync/atomic"
)

type SCTPListener struct {
	_fd    int32
	Mode   SCTPSocketMode
	Socket *SCTPConn
}

func (ln *SCTPListener) fd() int {
	return int(atomic.LoadInt32(&ln._fd))
}

func NewSCTPListener(laddr *SCTPAddr, init InitMsg, mode SCTPSocketMode, nonblocking bool) (*SCTPListener, error) {
	if laddr == nil {
		return nil, fmt.Errorf("Local SCTPAddr is required")
	}

	fd, err := createSocket(laddr, nil, init, mode, nonblocking)
	if err != nil {
		return nil, err
	}

	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		return nil, err
	}

	var socket *SCTPConn

	if mode == OneToMany {
		socket = newSCTPConn(fd)
	}

	return &SCTPListener{
		_fd:    int32(fd),
		Mode:   mode,
		Socket: socket,
	}, nil
}

// AcceptSCTP waits for and returns the next SCTP connection to the listener.
func (ln *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	if ln.Mode == OneToMany {
		return nil, fmt.Errorf("Calling Accept on OneToMany socket is invalid")
	}
	fd, _, err := syscall.Accept4(ln.fd(), 0)
	if err != nil {
		return nil, err
	}

	return newSCTPConn(fd), nil
}

// Accept waits for and returns the next connection connection to the listener.
func (ln *SCTPListener) Accept() (net.Conn, error) {
	return ln.AcceptSCTP()
}

func (ln *SCTPListener) Close() error {
	syscall.Shutdown(ln.fd(), syscall.SHUT_RDWR)
	return syscall.Close(ln.fd())
}

func (ln *SCTPListener) LocalAddr() net.Addr {
	if ln.Mode == OneToMany {
		return ln.Socket.LocalAddr()
	}

	addr, err := sctpGetAddrs(ln.fd(), 0, SCTP_GET_LOCAL_ADDRS)
	if err != nil {
		return nil
	}
	return addr
}

func (ln *SCTPListener) SCTPRead(b []byte) (int, *OOBMessage, int, error) {
	if ln.Mode == OneToOne {
		return -1, nil, -1, fmt.Errorf("Invalid state: SCTPRead on OneToOne socket not allowed")
	}

	return ln.Socket.SCTPRead(b)
}

func (ln *SCTPListener) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	if ln.Mode == OneToOne {
		return -1, fmt.Errorf("Invalid state: SCTPWrite on OneToOne socket not allowed")
	}

	return ln.Socket.SCTPWrite(b, info)
}
