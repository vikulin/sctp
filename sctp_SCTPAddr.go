package sctp

import (
	"bytes"
	"fmt"
	syscall "golang.org/x/sys/unix"
	"net"
	"strconv"
	"strings"
	"unsafe"
)

type SCTPAddr struct {
	IPAddrs       []net.IPAddr
	Port          int
	AddressFamily SCTPAddressFamily
}

func ResolveSCTPAddr(addressFamily SCTPAddressFamily, addrs string) (*SCTPAddr, error) {
	elems := strings.Split(addrs, "/")
	if len(elems) == 0 {
		return nil, fmt.Errorf("invalid input: %s", addrs)
	}

	lastE := elems[len(elems)-1]

	ipaddrs := make([]net.IPAddr, 0, len(elems))

	addr, port, err := net.SplitHostPort(lastE)
	if err != nil {
		return nil, fmt.Errorf("invalid input: Missing port: %s", addrs)

	} else {
		if port == "" {
			return nil, fmt.Errorf("invalid input: Missing port: %s", addrs)
		}
	}

	iPort, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid input: Non-integer port: %s", addrs)
	}

	elems[len(elems)-1] = addr

	for _, e := range elems {
		family := addressFamily.String()
		if !strings.Contains(e, ":") && addressFamily == SCTP6 {
			family = SCTP4.String()
		}
		ipa, err := net.ResolveIPAddr(family, e)

		if err != nil {
			return nil, err
		}

		if ipa.IP != nil {
			if ipa.IP.To4() == nil {
				if addressFamily == SCTP4 {
					return nil, fmt.Errorf("IPv6 address detected but addressFamily is IPv4")
				}
			}
			ipaddrs = append(ipaddrs, net.IPAddr{IP: ipa.IP, Zone: ipa.Zone})
		} else {
			var ip net.IPAddr
			switch addressFamily {
			case SCTP4:
				ip = net.IPAddr{IP: net.IPv4zero, Zone: ""}
			case SCTP6:
				ip = net.IPAddr{IP: net.IPv6zero, Zone: ""}
			default:
				return nil, fmt.Errorf("Unknown addressFamily: %s", addressFamily)
			}
			ipaddrs = append(ipaddrs, ip)
		}
	}

	return &SCTPAddr{
		IPAddrs:       ipaddrs,
		Port:          iPort,
		AddressFamily: addressFamily,
	}, nil
}

func (a *SCTPAddr) Network() string { return "sctp" }

func (a *SCTPAddr) ToRawSockAddrBuf() []byte {
	p := htons(uint16(a.Port))
	if len(a.IPAddrs) == 0 { // if a.IPAddrs list is empty - fall back to IPv4 zero addr
		s := syscall.RawSockaddrInet4{
			Family: syscall.AF_INET,
			Port:   p,
		}
		copy(s.Addr[:], net.IPv4zero)
		return toBuf(s)
	}
	buf := []byte{}
	for _, ip := range a.IPAddrs {
		ipBytes := ip.IP
		if len(ipBytes) == 0 {
			ipBytes = net.IPv4zero
		}
		if ip4 := ipBytes.To4(); ip4 != nil {
			s := syscall.RawSockaddrInet4{
				Family: syscall.AF_INET,
				Port:   p,
			}
			copy(s.Addr[:], ip4)
			buf = append(buf, toBuf(s)...)
		} else {
			var scopeid uint32
			ifi, err := net.InterfaceByName(ip.Zone)
			if err == nil {
				scopeid = uint32(ifi.Index)
			}
			s := syscall.RawSockaddrInet6{
				Family:   syscall.AF_INET6,
				Port:     p,
				Scope_id: scopeid,
			}
			copy(s.Addr[:], ipBytes)
			buf = append(buf, toBuf(s)...)
		}
	}
	return buf
}

func (a *SCTPAddr) String() string {
	var b bytes.Buffer

	for n, i := range a.IPAddrs {
		if i.IP.To4() != nil {
			b.WriteString(i.String())
		} else if i.IP.To16() != nil {
			if n == len(a.IPAddrs)-1 {
				b.WriteRune('[')
				b.WriteString(i.String())
				b.WriteRune(']')
			} else {
				b.WriteString(i.String())
			}
		}
		if n < len(a.IPAddrs)-1 {
			b.WriteRune('/')
		}
	}
	b.WriteRune(':')
	b.WriteString(strconv.Itoa(a.Port))
	return b.String()
}

func resolveFromRawAddr(ptr unsafe.Pointer, n int) (*SCTPAddr, error) {
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

func sctpGetAddrs(fd, id, optname int) (*SCTPAddr, error) {

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
	return resolveFromRawAddr(unsafe.Pointer(&param.addrs), int(param.addrNum))
}

//from https://github.com/golang/go
//Change: we check the first IP address in the list of candidate SCTP IP addresses
func (a *SCTPAddr) isWildcard() bool {
	if a == nil {
		return true
	}
	if 0 == len(a.IPAddrs) {
		return true
	}

	return a.IPAddrs[0].IP.IsUnspecified()
}

func favoriteAddrFamily(laddr *SCTPAddr, raddr *SCTPAddr) (family int, ipv6only bool) {

	if laddr != nil && raddr != nil {

		if laddr.AddressFamily == raddr.AddressFamily {
			return laddr.AddressFamily.ToSyscall(), (laddr.AddressFamily == SCTP6)
		}

		if supportsIPv4map() || !supportsIPv4() {
			return SCTP6.ToSyscall(), false
		}
	}

	return SCTP4.ToSyscall(), false
}
