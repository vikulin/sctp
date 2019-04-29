package sctp

import (
	"net"
	"sync/atomic"
	"time"

	syscall "golang.org/x/sys/unix"
)

type SCTPConn struct {
	fd int32
}

func NewSCTPConnection(af SCTPAddressFamily, options InitMsg, mode SCTPSocketMode, nonblocking bool) (*SCTPConn, error) {

	fd, err := SCTPSocket(af.ToSyscall(), mode)
	if err != nil {
		return nil, err
	}

	// close socket on error
	defer func(f int) {
		if err != nil {
			syscall.Close(f)
		}
	}(fd)

	if err = SCTPSetDefaultSockopts(fd, af.ToSyscall(), af == SCTP6Only); err != nil {
		return nil, err
	}

	if err = SCTPSetInitOpts(fd, options); err != nil {
		return nil, err
	}

	if err := syscall.SetNonblock(fd, nonblocking); err != nil {
		return nil, err
	}

	return &SCTPConn{
		fd: int32(fd),
	}, nil
}

func (c *SCTPConn) GetSocketMode() (SCTPSocketMode, error) {
	return SCTPGetSocketMode(c.FD())
}

func (c *SCTPConn) GetNonblocking() (bool, error) {
	return SCTPGetNonblocking(c.FD())
}

func (c *SCTPConn) SetNonblocking(val bool) error {
	return SCTPSetNonblocking(c.FD(), val)
}

func (c *SCTPConn) Listen() error {
	return SCTPListen(c.FD())
}

func (c *SCTPConn) Bind(laddr *SCTPAddr) error {
	return SCTPBind(c.FD(), laddr, SCTP_BINDX_ADD_ADDR)
}

func (c *SCTPConn) Connect(raddr *SCTPAddr) error {
	_, err := SCTPConnect(c.FD(), raddr)
	return err
}

func (c *SCTPConn) FD() int {
	return int(atomic.LoadInt32(&c.fd))
}

func (c *SCTPConn) Write(b []byte) (int, error) {
	return c.SCTPWrite(b, nil)
}

func (c *SCTPConn) Read(b []byte) (int, error) {
	n, _, _, err := c.SCTPRead(b)
	if n < 0 {
		n = 0
	}
	return n, err
}

func (c *SCTPConn) SetEvents(flags int) error {
	return SCTPSetEvents(c.FD(), flags)
}

func (c *SCTPConn) GetEvents() (int, error) {
	return SCTPGetEvents(c.FD())
}

func (c *SCTPConn) SetDefaultSentParam(info *SndRcvInfo) error {
	return SCTPSetDefaultSentParam(c.FD(), info)
}

func (c *SCTPConn) GetDefaultSentParam() (*SndRcvInfo, error) {
	return SCTPGetDefaultSentParam(c.FD())
}

func (c *SCTPConn) SCTPGetPrimaryPeerAddr() (*SCTPAddr, error) {
	return SCTPGetAddrs(c.FD(), 0, SCTP_PRIMARY_ADDR)
}

func (c *SCTPConn) SCTPLocalAddr(id uint16) (*SCTPAddr, error) {
	return SCTPGetLocalAddr(c.FD(), id)
}

func (c *SCTPConn) LocalAddr() net.Addr {
	addr, err := c.SCTPLocalAddr(0)
	if err != nil {
		return nil
	}
	return addr
}

func (c *SCTPConn) SCTPRemoteAddr(id uint16) (*SCTPAddr, error) {
	return SCTPGetRemoteAddr(c.FD(), id)
}

func (c *SCTPConn) RemoteAddr() net.Addr {
	addr, err := c.SCTPRemoteAddr(0)
	if err != nil {
		return nil
	}
	return addr
}

func (c *SCTPConn) PeelOff(id int32) (*SCTPConn, error) {
	fd, err := SCTPPeelOff(c.FD(), id)
	if err != nil {
		return nil, err
	}

	conn := &SCTPConn{
		fd: int32(fd),
	}

	blocking, err := c.GetNonblocking()
	if err != nil {
		return nil, err
	}

	if err := conn.SetNonblocking(blocking); err != nil {
		return nil, err
	}

	return conn, nil

}

func (c *SCTPConn) SetDeadline(t time.Time) error {
	return syscall.EOPNOTSUPP
}

func (c *SCTPConn) SetReadDeadline(t time.Time) error {
	return syscall.EOPNOTSUPP
}

func (c *SCTPConn) SetWriteDeadline(t time.Time) error {
	return syscall.EOPNOTSUPP
}

func (c *SCTPConn) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	return SCTPWrite(c.FD(), b, info)
}

func (c *SCTPConn) SCTPRead(b []byte) (int, *OOBMessage, int, error) {
	return SCTPRead(c.FD(), b)
}

func (c *SCTPConn) Close() error {
	return SCTPClose(c.FD())
}
