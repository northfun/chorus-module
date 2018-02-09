package crypto

import (
	"encoding/json"
	"testing"

	"github.com/Baptist-Publication/chorus-module/xlog"
)

func PrivKeyEd25519DeAndEn(t *testing.T, pwd []byte) {
	pwdCopy := make([]byte, len(pwd))
	copy(pwdCopy, pwd)
	pk, err := GenPrivKeyEd25519(pwd)
	if err != nil {
		t.Error("err when gen PrivKeyEd25519", err)
		return
	}
	defer pk.Destroy()
	beforeKey := pk.KeyBytes()
	beforeEn := pk.Bytes()
	if len(pwdCopy) == 0 {
		if len(beforeEn) != 0 {
			t.Error("pwd is nil, but encrypted isn't nil")
			return
		}
	} else {
		if len(beforeEn) == 0 {
			t.Error("pwd isn't nil, but encrypted is nil")
			return
		}
	}
	pkjson, err := json.Marshal(&pk)
	if err != nil {
		t.Error("json marshal err:", err)
		return
	}
	pk2 := &PrivKeyEd25519{}
	err = json.Unmarshal(pkjson, pk2)
	if err != nil {
		t.Error("json unmarshal err:", err)
		return
	}
	pk2.Decrypt(pwdCopy)
	defer pk2.Destroy()
	afterKey := pk2.KeyBytes()
	if string(beforeKey) != string(afterKey) {
		t.Logf("before: %X, after: %X", beforeKey, afterKey)
		t.Error("after json unmarshal, keybytes not equal")
		return
	}
	afterEn := pk2.Bytes()
	if string(beforeEn) != string(afterEn) {
		t.Logf("before: %X, after: %X", beforeEn, afterEn)
		t.Error("after json unmarshal, encrypted not equal")
		return
	}
}

func PrivKeyEd25519ResetPwd(t *testing.T, pwd, newpwd []byte) {
	t.Logf("pwd:%v, newpwd:%v", string(pwd), string(newpwd))
	pk, err := GenPrivKeyEd25519(nil)
	if err != nil {
		t.Error("err when gen PrivKeyEd25519", err)
		return
	}
	defer pk.Destroy()
	oriKey := pk.KeyBytes()

	var pkArr, pkArr3 PrivKeyEd25519Arr
	copy(pkArr[:], oriKey)  // ori with pwd, then reset with newpwd
	copy(pkArr3[:], oriKey) // ori with newpwd

	newpwdCp := make([]byte, len(newpwd))
	copy(newpwdCp[:], newpwd)

	pkPwd := &PrivKeyEd25519{}
	pkPwd3 := &PrivKeyEd25519{}
	pkPwd.InitAndEncrypt(&pkArr, pwd)
	pkPwd.ChangePwd(newpwdCp)
	defer pkPwd.Destroy()

	newKey := pkPwd.KeyBytes()
	newEn := pkPwd.Bytes()

	pkPwd3.InitAndEncrypt(&pkArr3, newpwd)
	defer pkPwd3.Destroy()
	newKey3 := pkPwd3.KeyBytes()
	newEn3 := pkPwd3.Bytes()

	if string(newEn) != string(newEn3) ||
		(string(oriKey) != string(newKey) && string(newKey) != string(newKey3)) {
		t.Logf("oriKey:%X\nnewEn:%X,newEn3:%X\nnewKey:%X,newKey3:%X\n", oriKey, newEn, newEn3, newKey, newKey3)
		t.Errorf("after reset encrypted not equal")
	}
}

func TestPrivKeyEd25519(t *testing.T) {
	defer xlog.DumpStack()
	pwd := []byte("hello")
	PrivKeyEd25519DeAndEn(t, pwd)
	pwdLong := []byte("hellohellohellohellohellohello")
	PrivKeyEd25519DeAndEn(t, pwdLong)
	pwdNull := []byte("")
	PrivKeyEd25519DeAndEn(t, pwdNull)

	pwd = []byte("hello")
	pwdLong = []byte("hellohellohellohellohellohello")
	PrivKeyEd25519ResetPwd(t, pwd, pwdLong)
	pwd = []byte("hello")
	pwdNull = []byte("")
	PrivKeyEd25519ResetPwd(t, pwd, pwdNull)
	pwd = []byte("hello")
	pwdNull = []byte("")
	PrivKeyEd25519ResetPwd(t, pwdNull, pwd)
}
