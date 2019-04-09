package sctp

import (
	"bytes"
	"encoding/binary"
)

//from https://github.com/golang/go
// Boolean to int.
func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}

func toBuf(v interface{}) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, nativeEndian, v)
	return buf.Bytes()
}

func htons(h uint16) uint16 {
	if nativeEndian == binary.LittleEndian {
		return (h << 8 & 0xff00) | (h >> 8 & 0xff)
	}
	return h
}

var ntohs = htons
