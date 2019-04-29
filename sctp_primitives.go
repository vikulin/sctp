package sctp

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"unsafe"

	syscall "golang.org/x/sys/unix"
)

func SCTPSocket(af int, mode SCTPSocketMode) (int, error) {
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

	return fd, nil
}

func SCTPGetSocketMode(fd int) (SCTPSocketMode, error) {
	optname := syscall.SO_TYPE
	optval := int(0)
	optlen := unsafe.Sizeof(optname)
	r0, _, err := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		syscall.SOL_SOCKET,
		uintptr(optname),
		uintptr(unsafe.Pointer(&optval)),
		uintptr(optlen),
		0)

	if err != 0 {
		return -1, err
	}

	switch r0 {
	case syscall.SOCK_STREAM:
		return OneToOne, nil
	case syscall.SOCK_SEQPACKET:
		return OneToMany, nil
	default:
		panic("Not an SCTP socket type!")
	}
}

func SCTPSetInitOpts(fd int, options InitMsg) error {
	optlen := unsafe.Sizeof(options)
	_, _, err := setsockopt(fd, SCTP_INITMSG, uintptr(unsafe.Pointer(&options)), uintptr(optlen))
	return err
}

func SCTPGetInitOpts(fd int) (InitMsg, error) {
	options := InitMsg{}
	optlen := unsafe.Sizeof(options)
	_, _, err := getsockopt(fd, SCTP_INITMSG, uintptr(unsafe.Pointer(&options)), uintptr(optlen))
	return options, err
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

func SCTPListen(fd int) error {
	return syscall.Listen(fd, syscall.SOMAXCONN)
}

func SCTPAccept(fd int) (int, error) {
	fd, _, err := syscall.Accept4(fd, 0)
	return fd, err
}

func SCTPWrite(fd int, b []byte, info *SndRcvInfo) (int, error) {
	var cbuf []byte
	if info != nil {
		cmsgBuf := toBuf(info)
		hdr := &syscall.Cmsghdr{
			Level: syscall.IPPROTO_SCTP,
			Type:  SCTP_CMSG_SNDRCV.i32(),
		}

		// bitwidth of hdr.Len is platform-specific,
		// so we use hdr.SetLen() rather than directly setting hdr.Len
		hdr.SetLen(syscall.CmsgSpace(len(cmsgBuf)))
		cbuf = append(toBuf(hdr), cmsgBuf...)
	}
	return syscall.SendmsgN(fd, b, cbuf, nil, 0)
}

func SCTPRead(fd int, b []byte) (dataCount int, oob *OOBMessage, flags int, err error) {

	oobBuffer := make([]byte, 254)
	oobCount := 0

	dataCount, oobCount, flags, _, err = syscall.Recvmsg(fd, b, oobBuffer, 0)

	if err != nil {
		return
	}

	if dataCount == 0 && oobCount == 0 {
		err = io.EOF
		return
	}

	if oobCount > 0 {
		oob, err = SCTPParseOOB(oobBuffer[:oobCount])
	}

	return
}

func SCTPClose(fd int) error {
	if fd > 0 {
		fdq := int32(fd)
		fd = int(atomic.SwapInt32(&fdq, -1))
		if fd > 0 {
			info := &SndRcvInfo{
				Flags: SCTP_EOF,
			}
			SCTPWrite(fd, nil, info)
			syscall.Shutdown(fd, syscall.SHUT_RDWR)
			return syscall.Close(fd)
		}
	}
	return syscall.EBADF
}

func SCTPSetNonblocking(fd int, nonblocking bool) error {
	return syscall.SetNonblock(fd, nonblocking)
}

func SCTPGetNonblocking(fd int) (bool, error) {
	flags, err := syscall.FcntlInt(uintptr(fd), syscall.F_GETFL, 0)
	if err != nil {
		return false, err
	}
	return flags&syscall.O_NONBLOCK > 0, nil
}

func SCTPGetLocalAddr(fd int, stream uint16) (*SCTPAddr, error) {
	return SCTPGetAddrs(fd, stream, SCTP_GET_LOCAL_ADDRS)
}

func SCTPGetRemoteAddr(fd int, stream uint16) (*SCTPAddr, error) {
	return SCTPGetAddrs(fd, stream, SCTP_GET_PEER_ADDRS)
}

func SCTPGetAddrs(fd int, id uint16, optname int) (*SCTPAddr, error) {

	type getaddrs struct {
		assocId int32
		addrNum uint32
		addrs   [4096]byte
	}
	param := getaddrs{
		assocId: int32(id),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(fd, uintptr(optname), uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}

	ptr, n := unsafe.Pointer(&param.addrs), int(param.addrNum)

	addr := &SCTPAddr{
		IPAddrs: make([]net.IPAddr, n),
	}

	switch family := (*(*syscall.RawSockaddrAny)(ptr)).Addr.Family; family {
	case syscall.AF_INET:
		addr.Port = int(ntohs(uint16((*(*syscall.RawSockaddrInet4)(ptr)).Port)))
		tmp := syscall.RawSockaddrInet4{}
		size := unsafe.Sizeof(tmp)
		for i := 0; i < n; i++ {
			a := *(*syscall.RawSockaddrInet4)(unsafe.Pointer(
				uintptr(ptr) + size*uintptr(i)))
			addr.IPAddrs[i] = net.IPAddr{IP: a.Addr[:]}
		}
	case syscall.AF_INET6:
		addr.Port = int(ntohs(uint16((*(*syscall.RawSockaddrInet4)(ptr)).Port)))
		tmp := syscall.RawSockaddrInet6{}
		size := unsafe.Sizeof(tmp)
		for i := 0; i < n; i++ {
			a := *(*syscall.RawSockaddrInet6)(unsafe.Pointer(
				uintptr(ptr) + size*uintptr(i)))
			var zone string
			ifi, err := net.InterfaceByIndex(int(a.Scope_id))
			if err == nil {
				zone = ifi.Name
			}
			addr.IPAddrs[i] = net.IPAddr{IP: a.Addr[:], Zone: zone}
		}
	default:
		return nil, fmt.Errorf("unknown address family: %d", family)
	}
	return addr, nil
}

func SCTPGetDefaultSentParam(fd int) (*SndRcvInfo, error) {
	info := &SndRcvInfo{}
	optlen := unsafe.Sizeof(*info)
	_, _, err := getsockopt(fd, SCTP_DEFAULT_SENT_PARAM, uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&optlen)))
	return info, err
}

func SCTPSetDefaultSentParam(fd int, info *SndRcvInfo) error {
	optlen := unsafe.Sizeof(*info)
	_, _, err := setsockopt(fd, SCTP_DEFAULT_SENT_PARAM, uintptr(unsafe.Pointer(info)), uintptr(optlen))
	return err
}

func SCTPPeelOff(fd int, associd int32) (int, error) {
	type peeloffArg struct {
		assocId int32
		sd      int
	}
	param := peeloffArg{
		assocId: associd,
	}
	optlen := unsafe.Sizeof(param)
	r0, _, err := getsockopt(fd, SCTP_SOCKOPT_PEELOFF, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return -1, err
	}
	// Note, for some reason, the struct isn't getting populated after the syscall. But the return values are right, so we use r0 which is our fd that we want.
	if param.sd == -1 || r0 == 0 {
		return -1, fmt.Errorf("Returned fd is negative!")
	}
	return int(r0), nil

}

func SCTPSetEvents(fd, flags int) error {

	var d, a, ad, sf, p, sh, pa, ada, au, se uint8
	if flags&SCTP_EVENT_DATA_IO > 0 {
		d = 1
	}
	if flags&SCTP_EVENT_ASSOCIATION > 0 {
		a = 1
	}
	if flags&SCTP_EVENT_ADDRESS > 0 {
		ad = 1
	}
	if flags&SCTP_EVENT_SEND_FAILURE > 0 {
		sf = 1
	}
	if flags&SCTP_EVENT_PEER_ERROR > 0 {
		p = 1
	}
	if flags&SCTP_EVENT_SHUTDOWN > 0 {
		sh = 1
	}
	if flags&SCTP_EVENT_PARTIAL_DELIVERY > 0 {
		pa = 1
	}
	if flags&SCTP_EVENT_ADAPTATION_LAYER > 0 {
		ada = 1
	}
	if flags&SCTP_EVENT_AUTHENTICATION > 0 {
		au = 1
	}
	if flags&SCTP_EVENT_SENDER_DRY > 0 {
		se = 1
	}
	param := EventSubscribe{
		DataIO:          d,
		Association:     a,
		Address:         ad,
		SendFailure:     sf,
		PeerError:       p,
		Shutdown:        sh,
		PartialDelivery: pa,
		AdaptationLayer: ada,
		Authentication:  au,
		SenderDry:       se,
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := setsockopt(fd, SCTP_EVENTS, uintptr(unsafe.Pointer(&param)), uintptr(optlen))
	return err
}

func SCTPGetEvents(fd int) (int, error) {
	param := EventSubscribe{}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(fd, SCTP_EVENTS, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return 0, err
	}
	var flags int
	if param.DataIO > 0 {
		flags |= SCTP_EVENT_DATA_IO
	}
	if param.Association > 0 {
		flags |= SCTP_EVENT_ASSOCIATION
	}
	if param.Address > 0 {
		flags |= SCTP_EVENT_ADDRESS
	}
	if param.SendFailure > 0 {
		flags |= SCTP_EVENT_SEND_FAILURE
	}
	if param.PeerError > 0 {
		flags |= SCTP_EVENT_PEER_ERROR
	}
	if param.Shutdown > 0 {
		flags |= SCTP_EVENT_SHUTDOWN
	}
	if param.PartialDelivery > 0 {
		flags |= SCTP_EVENT_PARTIAL_DELIVERY
	}
	if param.AdaptationLayer > 0 {
		flags |= SCTP_EVENT_ADAPTATION_LAYER
	}
	if param.Authentication > 0 {
		flags |= SCTP_EVENT_AUTHENTICATION
	}
	if param.SenderDry > 0 {
		flags |= SCTP_EVENT_SENDER_DRY
	}
	return flags, nil
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
func SCTPSetDefaultSockopts(s int, family int, ipv6only bool) error {
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

func SCTPParseOOB(b []byte) (*OOBMessage, error) {
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

func SCTPParseNotification(b []byte) (*Notification, error) {
	return &Notification{Data: b}, nil
}
