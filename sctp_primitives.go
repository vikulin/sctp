package sctp

import (
	"fmt"
	syscall "golang.org/x/sys/unix"
	"os"
	"unsafe"
)

func createSocket(laddr, raddr *SCTPAddr, init InitMsg, mode SCTPSocketMode) (int, error) {

	if laddr == nil && raddr == nil {
		return -1, fmt.Errorf("Neither local or remote address provided")
	}

	af, ipv6only := favoriteAddrFamily(laddr, raddr)

	socketType := syscall.SOCK_SEQPACKET

	if mode == OneToOne {
		socketType = syscall.SOCK_STREAM
	}

	fd, err := syscall.Socket(
		af,
		socketType,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return -1, err
	}

	// close socket on error
	defer func() {
		if err != nil {
			syscall.Close(fd)
		}
	}()
	if err = setDefaultSockopts(fd, af, ipv6only); err != nil {
		return -1, err
	}
	err = setInitOpts(fd, init)
	if err != nil {
		return -1, err
	}

	if laddr != nil {
		err := SCTPBind(fd, laddr, SCTP_BINDX_ADD_ADDR)
		if err != nil {
			return -1, err
		}
	}

	return fd, nil
}

// setInitOpts sets options for an SCTP association initialization
// see https://tools.ietf.org/html/rfc4960#page-25
func setInitOpts(fd int, options InitMsg) error {
	optlen := unsafe.Sizeof(options)
	_, _, err := setsockopt(fd, SCTP_INITMSG, uintptr(unsafe.Pointer(&options)), uintptr(optlen))
	return err
}

func setNumOstreams(fd, num int) error {
	return setInitOpts(fd, InitMsg{NumOstreams: uint16(num)})
}

func SCTPConnect(fd int, addr *SCTPAddr) (int, error) {
	buf := addr.ToRawSockAddrBuf()
	param := GetAddrsOld{
		AddrNum: int32(len(buf)),
		Addrs:   uintptr(uintptr(unsafe.Pointer(&buf[0]))),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(fd, SCTP_SOCKOPT_CONNECTX3, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err == nil {
		return int(param.AssocID), nil
	} else if err != syscall.ENOPROTOOPT {
		return 0, err
	}
	r0, _, err := setsockopt(fd, SCTP_SOCKOPT_CONNECTX, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return int(r0), err
}

func SCTPBind(fd int, addr *SCTPAddr, flags int) error {
	var option uintptr
	switch flags {
	case SCTP_BINDX_ADD_ADDR:
		option = SCTP_SOCKOPT_BINDX_ADD
	case SCTP_BINDX_REM_ADDR:
		option = SCTP_SOCKOPT_BINDX_REM
	default:
		return syscall.EINVAL
	}

	buf := addr.ToRawSockAddrBuf()
	_, _, err := setsockopt(fd, option, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

func setsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	// FIXME: syscall.SYS_SETSOCKOPT is undefined on 386
	r0, r1, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		SOL_SCTP,
		optname,
		optval,
		optlen,
		0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

//from https://github.com/golang/go
//Changes: it is for SCTP only
func setDefaultSockopts(s int, family int, ipv6only bool) error {
	if family == syscall.AF_INET6 {
		// Allow both IP versions even if the OS default
		// is otherwise. Note that some operating systems
		// never admit this option.
		syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, boolint(ipv6only))
	}
	// Allow broadcast.
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1))
}

func getsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	// FIXME: syscall.SYS_GETSOCKOPT is undefined on 386
	r0, r1, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		SOL_SCTP,
		optname,
		optval,
		optlen,
		0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

func parseOOB(b []byte) (*OOBMessage, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, err
	}
	for _, msg := range msgs {
		m := &OOBMessage{msg}
		if m.IsSCTP() {
			return m, nil
		}
	}
	return nil, nil
}

func parseNotification(b []byte) (*Notification, error) {
	return &Notification{Data: b}, nil
}
