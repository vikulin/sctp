package sctp

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	syscall "golang.org/x/sys/unix"
)

func TestNonBlockingServerOneToMany(t *testing.T) {
	addr, _ := ResolveSCTPAddr(SCTP4, "127.0.0.1:0")
	ln, err := NewSCTPListener(addr, InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS}, OneToMany, true)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	ln.Socket.SubscribeEvents(SCTP_EVENT_DATA_IO)

	raddr := ln.LocalAddr().(*SCTPAddr)

	go func() {
		type ready struct {
			SndRcvInfo *SndRcvInfo
			Data       []byte
		}
		b := make(map[int32]map[uint16]bytes.Buffer)
		c := make([]*ready, 0)
		for {
			buf := make([]byte, 64)
			n, oob, flags, err := ln.SCTPRead(buf)
			if err != nil {
				if err == syscall.EAGAIN {
					t.Logf("READ EAGAIN\n")
					goto WRITE
				}
				t.Errorf("Server connection read err: %v", err)
				return
			}

			t.Logf("DATA: %v, N: %d, OOB: %#+v, FLAGS: %d, ERR: %v\n", buf[:n], n, oob, flags, err)

			if flags&MSG_EOR > 0 {
				info := oob.GetSndRcvInfo()
				assocId := info.AssocID
				if _, ok := b[assocId]; !ok {
					b[assocId] = make(map[uint16]bytes.Buffer)
				}
				bucket := b[assocId]

				stream := bucket[info.Stream]
				stream.Write(buf[:n])

				data := stream.Bytes()
				dataCopy := make([]byte, stream.Len())
				copy(dataCopy, data)

				stream.Reset()

				sndrcv := &SndRcvInfo{Stream: info.Stream, AssocID: info.AssocID}
				c = append(c, &ready{SndRcvInfo: sndrcv, Data: dataCopy})
				t.Logf("Write data queued: %#+v\n", c)

			} else {
				info := oob.GetSndRcvInfo()
				assocId := info.AssocID
				if _, ok := b[assocId]; !ok {
					b[assocId] = make(map[uint16]bytes.Buffer)
				}
				bucket := b[assocId]

				stream := bucket[info.Stream]
				stream.Write(buf[:n])

				t.Logf("No EOR\n")
			}
		WRITE:
			for {
				if len(c) > 0 {
					var r *ready
					r = c[0]
					c = c[1:]
					t.Logf("Writing: %v, %#+v\n", r.Data, r.SndRcvInfo)
					_, err := ln.SCTPWrite(r.Data, r.SndRcvInfo)
					if err != nil {
						if err == syscall.EWOULDBLOCK {
							t.Logf("WRITE EWOULDBLOCK\n")
							c = append(c, r)
							break
						}
						t.Logf("Something went wrong?: %v", err)
					}
				} else {
					t.Logf("No queued writes\n")
					break
				}
			}

			<-time.Tick(time.Millisecond * 10)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < STREAM_TEST_CLIENTS; i++ {
		wg.Add(1)
		go func(test int) {
			defer wg.Done()

			conn, err := NewSCTPConnection(nil, raddr,
				InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS},
				OneToOne, false)
			if err != nil {
				t.Errorf("failed to dial address %s, test #%d: %v", raddr.String(), test, err)
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

	wg.Wait()
	ln.Close()
}
