package sctp

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"
)

const (
	STREAM_TEST_CLIENTS = 10
	STREAM_TEST_STREAMS = 100
)

var r *rand.Rand

func init() {
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func randomString(length int) string {
	var rMu sync.Mutex
	rMu.Lock()
	defer rMu.Unlock()
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[r.Intn(len(chars))]
	}
	return string(result)
}

func TestStreamsOneToOne(t *testing.T) {
	addr, _ := ResolveSCTPAddr(SCTP4, "127.0.0.1:0")
	ln, err := NewSCTPListener(addr, InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS}, OneToOne)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr = ln.LocalAddr().(*SCTPAddr)

	go func() {
		for {
			c, err := ln.Accept()
			sconn := c.(*SCTPConn)
			if err != nil {
				t.Errorf("failed to accept: %v", err)
				return
			}
			defer sconn.Close()

			sconn.SubscribeEvents(SCTP_EVENT_DATA_IO | SCTP_EVENT_ASSOCIATION)

			go func() {
				totalrcvd := 0
				var b bytes.Buffer
				for {
					buf := make([]byte, 64)
					n, oob, flags, err := sconn.SCTPRead(buf)
					if err != nil {
						if err == io.EOF || err == io.ErrUnexpectedEOF {
							if n == 0 {
								break
							}
							t.Logf("EOF on server connection. Total bytes received: %d, bytes received: %d", totalrcvd, n)
						} else {
							t.Errorf("Server connection read err: %v. Total bytes received: %d, bytes received: %d", err, totalrcvd, n)
							return
						}
					}

					b.Write(buf[:n])

					if flags&MSG_NOTIFICATION > 0 {
						if !(flags&MSG_EOR > 0) {
							t.Log("buffer not large enough for notification")
							continue
						}
					} else if flags&MSG_EOR > 0 {
						info := oob.GetSndRcvInfo()
						data := b.Bytes()
						n, err = sconn.SCTPWrite(data, &SndRcvInfo{
							Stream: info.Stream,
							PPID:   info.PPID,
						})
						if err != nil {
							t.Error(err)
							return
						}
					} else {
						t.Logf("No flags match?: %v", flags&MSG_EOR)
					}

					b.Reset()
				}
			}()
		}
	}()

	wait := make(chan struct{})
	i := 0
	for ; i < STREAM_TEST_CLIENTS; i++ {
		go func(test int) {
			defer func() { wait <- struct{}{} }()
			conn, err := NewSCTPConnection(nil, addr,
				InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS},
				OneToOne)
			if err != nil {
				t.Errorf("failed to dial address %s, test #%d: %v", addr.String(), test, err)
				return
			}
			defer conn.Close()
			conn.SubscribeEvents(SCTP_EVENT_DATA_IO)
			for ppid := uint16(0); ppid < STREAM_TEST_STREAMS; ppid++ {
				info := &SndRcvInfo{
					Stream: uint16(ppid),
					PPID:   uint32(ppid),
				}
				randomLen := r.Intn(5) + 1
				text := fmt.Sprintf("[%s,%d,%d]", randomString(randomLen), test, ppid)
				n, err := conn.SCTPWrite([]byte(text), info)
				if err != nil {
					t.Errorf("failed to write %s, len: %d, err: %v, bytes written: %d, info: %+v", text, len(text), err, n, info)
					return
				}
				var b bytes.Buffer
				for {
					buf := make([]byte, 64)
					cn, oob, flags, err := conn.SCTPRead(buf)
					if err != nil {
						if err == io.EOF || err == io.ErrUnexpectedEOF {
							if cn == 0 {
								break
							}
							t.Logf("EOF on server connection. Total bytes received: %d, bytes received: %d", len(b.Bytes()), cn)
						} else {
							t.Errorf("Client connection read err: %v. Total bytes received: %d, bytes received: %d", err, len(b.Bytes()), cn)
							return
						}
					}

					b.Write(buf[:cn])

					if flags&MSG_NOTIFICATION > 0 {
						if !(flags&MSG_EOR > 0) {
							t.Log("buffer not large enough for notification")
							continue
						}
					} else if flags&MSG_EOR > 0 {
						if oob.GetSndRcvInfo().Stream != ppid {
							t.Errorf("Mismatched PPIDs: %d != %d", oob.GetSndRcvInfo().Stream, ppid)
							return
						}
						rtext := string(b.Bytes())
						b.Reset()
						if rtext != text {
							t.Fatalf("Mismatched payload: %s != %s", []byte(rtext), []byte(text))
						}

						break
					}
				}
			}
		}(i)
	}
	for ; i > 0; i-- {
		select {
		case <-wait:
		case <-time.After(time.Second * 30):
			close(wait)
			t.Fatal("timed out")
		}
	}
}

func TestStreamsOneToMany(t *testing.T) {
	addr, _ := ResolveSCTPAddr(SCTP4, "127.0.0.1:0")
	ln, err := NewSCTPListener(addr, InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS}, OneToMany)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr = ln.LocalAddr().(*SCTPAddr)

	ln.Socket.SubscribeEvents(SCTP_EVENT_DATA_IO)

	t.Log("Spinning up server goroutine")
	go func() {
		var b bytes.Buffer
		for {
			buf := make([]byte, 64)
			n, oob, flags, err := ln.SCTPRead(buf)
			t.Logf("Server read data count: %d", n)
			if err != nil {
				t.Errorf("Server connection read err: %v", err)
				return
			}

			b.Write(buf[:n])

			if flags&MSG_EOR > 0 {
				info := oob.GetSndRcvInfo()
				data := b.Bytes()
				t.Logf("Server received data: %s", string(data))
				n, err = ln.SCTPWrite(data, &SndRcvInfo{
					Stream:  info.Stream,
					PPID:    info.PPID,
					AssocID: info.AssocID,
				})

				b.Reset()

				if err != nil {
					t.Error(err)
					return
				}
			} else {
				t.Logf("No flags match?: %v", flags&MSG_EOR)
			}

		}
	}()

	wait := make(chan struct{})
	i := 0
	t.Log("Spinning up clients")
	for ; i < STREAM_TEST_CLIENTS; i++ {
		go func(test int) {
			defer func() { wait <- struct{}{} }()
			t.Log("Creating client connection")
			conn, err := NewSCTPConnection(nil, addr,
				InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS},
				OneToOne)
			if err != nil {
				t.Errorf("failed to dial address %s, test #%d: %v", addr.String(), test, err)
				return
			}
			defer conn.Close()
			conn.SubscribeEvents(SCTP_EVENT_DATA_IO)
			for ppid := uint16(0); ppid < STREAM_TEST_STREAMS; ppid++ {
				info := &SndRcvInfo{
					Stream: uint16(ppid),
					PPID:   uint32(ppid),
				}
				randomLen := r.Intn(5) + 1
				text := fmt.Sprintf("[%s,%d,%d]", randomString(randomLen), test, ppid)
				t.Logf("Sending data to server: %v", text)
				n, err := conn.SCTPWrite([]byte(text), info)
				if err != nil {
					t.Errorf("failed to write %s, len: %d, err: %v, bytes written: %d, info: %+v", text, len(text), err, n, info)
					return
				}
				var b bytes.Buffer
				for {
					buf := make([]byte, 64)
					cn, oob, flags, err := conn.SCTPRead(buf)
					t.Logf("Client read data count: %d", cn)
					if err != nil {
						if err == io.EOF || err == io.ErrUnexpectedEOF {
							if cn == 0 {
								break
							}
							t.Logf("EOF on server connection. Total bytes received: %d, bytes received: %d", len(b.Bytes()), cn)
						} else {
							t.Errorf("Client connection read err: %v. Total bytes received: %d, bytes received: %d", err, len(b.Bytes()), cn)
							return
						}
					}

					b.Write(buf[:cn])

					if flags&MSG_EOR > 0 {
						if oob.GetSndRcvInfo().Stream != ppid {
							t.Errorf("Mismatched PPIDs: %d != %d", oob.GetSndRcvInfo().Stream, ppid)
							return
						}
						rtext := string(b.Bytes())
						b.Reset()
						if rtext != text {
							t.Fatalf("Mismatched payload: %s != %s", []byte(rtext), []byte(text))
						}
						t.Log("Data read from server matched what we sent")

						break
					}
				}
			}
		}(i)
	}
	for ; i > 0; i-- {
		select {
		case <-wait:
		case <-time.After(time.Second * 10):
			close(wait)
			t.Fatal("timed out")
		}
	}
	ln.Close()
}
