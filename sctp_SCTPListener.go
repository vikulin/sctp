package sctp

import (
	"fmt"
	"net"
)

type SCTPListener struct {
	SCTPConn
	socketMode SCTPSocketMode
}

func NewSCTPListener(laddr *SCTPAddr, init InitMsg, mode SCTPSocketMode, nonblocking bool) (*SCTPListener, error) {
	if laddr == nil {
		return nil, fmt.Errorf("Local SCTPAddr is required")
	}

	conn, err := NewSCTPConnection(laddr, laddr.AddressFamily, init, mode, nonblocking)
	if err != nil {
		return nil, err
	}

	ln := &SCTPListener{SCTPConn: *conn, socketMode: mode}
	ln.socketMode = mode

	if err := ln.Bind(laddr); err != nil {
		return nil, err
	}

	if err := ln.Listen(); err != nil {
		return nil, err
	}
	return ln, nil
}

// AcceptSCTP waits for and returns the next SCTP connection to the listener.
func (ln *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	if ln.socketMode == OneToMany {
		return nil, fmt.Errorf("Calling Accept on OneToMany socket is invalid")
	}

	fd, err := SCTPAccept(ln.FD())
	if err != nil {
		return nil, err
	}
	blocking, err := ln.GetNonblocking()
	if err != nil {
		return nil, err
	}
	conn := &SCTPConn{fd: int32(fd)}

	err = conn.SetNonblocking(blocking)
	if err != nil {
		return nil, err
	}

	return conn, nil

}

// Accept waits for and returns the next connection connection to the listener.
func (ln *SCTPListener) Accept() (net.Conn, error) {
	return ln.AcceptSCTP()
}

func (ln *SCTPListener) SCTPRead(b []byte) (int, *OOBMessage, int, error) {
	if ln.socketMode == OneToOne {
		return -1, nil, -1, fmt.Errorf("Invalid state: SCTPRead on OneToOne socket not allowed")
	}

	return ln.SCTPConn.SCTPRead(b)
}

func (ln *SCTPListener) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	if ln.socketMode == OneToOne {
		return -1, fmt.Errorf("Invalid state: SCTPWrite on OneToOne socket not allowed")
	}

	return ln.SCTPConn.SCTPWrite(b, info)
}

func (ln *SCTPListener) Addr() net.Addr {
	return ln.SCTPConn.LocalAddr()
}
