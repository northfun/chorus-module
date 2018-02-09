package crypto

import (
	"testing"
)

func Test_Crypto(t *testing.T) {
	text := "aa"
	pwd := "aa"
	rpwd := "aaaaaa"
	rspwd := "a"
	npwd := ""
	ret, err := Encrypt([]byte(text), []byte(pwd))
	if err != nil {
		t.Error(err)
	}
	deret, err := Decrypt(ret, []byte(pwd))
	if err != nil {
		t.Error(err)
	}
	if string(deret) != string(text) {
		t.Error("not equal")
	}

	deret, err = Decrypt(ret, []byte(rpwd))
	if err == nil && string(deret) == string(text) {
		t.Error("decrypt ok with wrong long pwd")
	}
	deret, err = Decrypt(ret, []byte(rspwd))
	if err == nil && string(deret) == string(text) {
		t.Error("decrypt ok with wrong short pwd")
	}
	deret, err = Decrypt(ret, []byte(npwd))
	if err == nil && string(deret) == string(text) {
		t.Error("decrypt ok with nil pwd")
	}
}
