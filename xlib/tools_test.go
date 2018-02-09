package xlib

import (
	"bytes"
	crand "crypto/rand"
	"testing"
)

func TestSortInt64Slc(t *testing.T) {
	var slc = []int64{1, 129, 20, 4, 45, 66}
	Int64Slice(slc).Sort()
	pre := slc[0]
	for i := range slc {
		if pre > slc[i] {
			t.Error("sort err")
			return
		}
		pre = slc[i]
	}
}

func randBytes(size int) []byte {
	b := make([]byte, size)
	_, err := crand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func checkSerialBytes(t *testing.T, bys []byte) {
	var wbuffer bytes.Buffer
	if err := WriteBytes(&wbuffer, bys); err != nil {
		t.Error("writeBytes err:", err)
		return
	}
	wbys := wbuffer.Bytes()

	rbuffer := bytes.NewReader(wbys)
	ret, err := ReadBytes(rbuffer)
	if err != nil {
		t.Error("readBytes err:", err)
		return
	}
	//fmt.Printf("origin:%X\nwrite bytes:%X\nre-read bytes:%X\n", bys, wbys, ret)
	if string(ret) != string(bys) {
		t.Error("read error, not equal")
	}
}

func TestSerialBytes(t *testing.T) {
	slc0 := randBytes(0)
	checkSerialBytes(t, slc0)

	slc32 := randBytes(32)
	checkSerialBytes(t, slc32)

	slc64 := randBytes(64)
	checkSerialBytes(t, slc64)

	slc128 := randBytes(128)
	checkSerialBytes(t, slc128)
}
