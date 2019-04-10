package sctp

/*
	#include<sys/socket.h>
	#include<stdint.h>
	#include<linux/sctp.h>
*/
import "C"
import (
	syscall "golang.org/x/sys/unix"
	"unsafe"
)

type EventSubscribe struct {
	DataIO          uint8
	Association     uint8
	Address         uint8
	SendFailure     uint8
	PeerError       uint8
	Shutdown        uint8
	PartialDelivery uint8
	AdaptationLayer uint8
	Authentication  uint8
	SenderDry       uint8
}

type InitMsg struct {
	NumOstreams    uint16
	MaxInstreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout uint16
}

func NewDefaultInitMsg() *InitMsg {
	return &InitMsg{
		NumOstreams: uint16(10),
	}
}

type SndRcvInfo struct {
	Stream  uint16
	SSN     uint16
	Flags   uint16
	_       uint16
	PPID    uint32
	Context uint32
	TTL     uint32
	TSN     uint32
	CumTSN  uint32
	AssocID int32
}

type NxtInfo struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Length  uint32
	AssocID int32
}

type SndInfo struct {
	Stream  uint16
	Flags   uint16
	PPID    uint32
	Context uint32
	AssocID int32
}

type GetAddrsOld struct {
	AssocID int32
	AddrNum int32
	Addrs   uintptr
}

type NotificationHeader struct {
	Type   SCTPNotificationType
	Flags  uint16
	Length uint32
}

type Notification struct {
	Data []byte
}

func (n *Notification) Header() *NotificationHeader {
	return (*NotificationHeader)(unsafe.Pointer(&n.Data[0]))
}

func (n *Notification) Type() SCTPNotificationType {
	return n.Header().Type
}

func (n *Notification) GetAssociationChange() *AssociationChange {
	return (*AssociationChange)(unsafe.Pointer(&n.Data[0]))
}

func (n *Notification) GetPeerAddrChange() *PeerAddrChange {
	return (*PeerAddrChange)(unsafe.Pointer(&n.Data[0]))
}

func (n *Notification) GetRemoteError() *RemoteError {
	return (*RemoteError)(unsafe.Pointer(&n.Data[0]))
}

func (n *Notification) GetSendFailed() *SendFailed {
	return (*SendFailed)(unsafe.Pointer(&n.Data[0]))
}

func (n *Notification) GetAdaptationIndication() *AdaptationIndication {
	return (*AdaptationIndication)(unsafe.Pointer(&n.Data[0]))
}

func (n *Notification) GetPartialDelivery() *PartialDelivery {
	return (*PartialDelivery)(unsafe.Pointer(&n.Data[0]))
}

func (n *Notification) GetAuthentication() *Authentication {
	return (*Authentication)(unsafe.Pointer(&n.Data[0]))
}

func (n *Notification) GetSenderDry() *SenderDry {
	return (*SenderDry)(unsafe.Pointer(&n.Data[0]))
}

//type AssociationChange C.struct_sctp_assoc_change

type AssociationChange struct {
	Type            SCTPNotificationType
	Flags           uint16
	Length          uint32
	State           SCTPState
	Error           uint16
	OutboundStreams uint16
	InboundStreams  uint16
	AssocID         int32
	Info            []byte
}

type PeerAddrChange struct {
	Type    SCTPNotificationType
	Length  uint32
	Addr    C.struct_sockaddr_storage
	State   PeerChangeState
	Error   uint32
	AssocID int32
}

type RemoteError struct {
	Type    SCTPNotificationType
	Flags   uint16
	Length  uint32
	Error   uint16
	AssocID int32
	Info    []byte
}

type SendFailed struct {
	Type    SCTPNotificationType
	Flags   uint16
	Length  uint32
	Error   uint16
	SndInfo SndInfo
	AssocID int32
	Data    []byte
}

type AdaptationIndication struct {
	Type       SCTPNotificationType
	Flags      uint16
	Length     uint32
	Indication uint32
	AssocID    int32
}

type PartialDelivery struct {
	Type           SCTPNotificationType
	Flags          uint16
	Length         uint32
	Indication     uint32
	StreamID       uint32
	SequenceNumber uint32
}

type Authentication struct {
	Type       SCTPNotificationType
	Flags      uint16
	Length     uint32
	KeyNumber  uint16
	Indication uint32
	AssocID    int32
}

type SenderDry struct {
	Type    SCTPNotificationType
	Flags   uint16
	Length  uint32
	AssocID int32
}

type OOBMessage struct {
	syscall.SocketControlMessage
}

func (o *OOBMessage) IsSCTP() bool {
	return o.Header.Level == syscall.IPPROTO_SCTP
}

func (o *OOBMessage) Type() SCTPCmsgType {
	return SCTPCmsgType(o.Header.Type)
}

func (o *OOBMessage) GetSndRcvInfo() *SndRcvInfo {
	return (*SndRcvInfo)(unsafe.Pointer(&o.Data[0]))
}

func (o *OOBMessage) GetSndInfo() *SndInfo {
	return (*SndInfo)(unsafe.Pointer(&o.Data[0]))
}

func (o *OOBMessage) GetNxtInfo() *NxtInfo {
	return (*NxtInfo)(unsafe.Pointer(&o.Data[0]))
}
