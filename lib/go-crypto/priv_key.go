// Copyright 2017 Baptist-Publication Information Technology Services Co.,Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unsafe"

	"github.com/Baptist-Publication/chorus-module/lib/ed25519"
	"github.com/Baptist-Publication/chorus-module/lib/ed25519/extra25519"
	. "github.com/Baptist-Publication/chorus-module/lib/go-common"
	libcrypto "github.com/Baptist-Publication/chorus-module/xlib/crypto"
	"github.com/awnumar/memguard"
	secp256k1 "github.com/btcsuite/btcd/btcec"
)

type StPrivKey struct {
	PrivKey
}

func (p StPrivKey) MarshalJSON() ([]byte, error) {
	if p.PrivKey == nil {
		return json.Marshal(nil)
	}
	return p.PrivKey.MarshalJSON()
}

func (p *StPrivKey) UnmarshalJSON(data []byte) error {
	var dec []interface{}
	err := json.Unmarshal(data, &dec)
	if err != nil {
		return err
	}
	if len(dec) == 0 {
		return nil
	}
	if len(dec) < 2 {
		return errors.New("params missing at unmarshalJson privkey")
	}
	switch byte(dec[0].(float64)) {
	case PrivKeyTypeEd25519:
		p.PrivKey = &PrivKeyEd25519{}
	case PrivKeyTypeSecp256k1:
		p.PrivKey = &PrivKeySecp256k1{}
	default:
		return errors.New("wrong type of pubkey")
	}
	return p.PrivKey.UnmarshalJSON(data)
}

func (p *StPrivKey) String() string {
	if p == nil || p.PrivKey == nil {
		return ""
	}
	return p.PrivKey.String()
}

// PrivKey is part of PrivAccount and state.PrivValidator.
type PrivKey interface {
	Sign(msg []byte) Signature
	Decrypt(pwd []byte) error
	PubKey() PubKey
	Equals(PrivKey) bool
	String() string
	Destroy()
	json.Marshaler
	json.Unmarshaler
}

// Types of PrivKey implementations
const (
	PrivKeyTypeEd25519   = byte(0x01)
	PrivKeyTypeSecp256k1 = byte(0x02)
)

//-------------------------------------

type PrivKeyEd25519Arr = [64]byte

// Implements PrivKey
type PrivKeyEd25519 struct {
	//[64]byte
	encrypted []byte
	mg        *memguard.LockedBuffer
}

func (privKey *PrivKeyEd25519) InitAndEncrypt(pkArr *PrivKeyEd25519Arr, pwd []byte) error {
	var err error
	if len(pwd) != 0 {
		privKey.encrypted, err = libcrypto.Encrypt((*pkArr)[:], pwd)
		libcrypto.WipeBytes(pwd)
		if err != nil {
			return err
		}
	} else {
		privKey.encrypted = []byte{}
	}
	// pkBytes will be wiped by memguard
	if privKey.mg != nil && !privKey.mg.IsDestroyed() {
		privKey.mg.Destroy()
	}
	privKey.mg, err = memguard.NewImmutableFromBytes((*pkArr)[:])
	return err
}

func (privKey *PrivKeyEd25519) ChangePwd(pwd []byte) error {
	pkArr := privKey.arrayPtr()
	var newPkArr PrivKeyEd25519Arr
	copy(newPkArr[:], (*pkArr)[:])
	return privKey.InitAndEncrypt(&newPkArr, pwd)
}

func (privKey *PrivKeyEd25519) InitAndDecrypt(encrypted []byte, pwd []byte) error {
	if len(encrypted) == 0 {
		return errors.New("ciphertext is nil")
	}
	privKey.encrypted = encrypted
	return privKey.Decrypt(pwd)
}

func (privKey *PrivKeyEd25519) Decrypt(pwd []byte) error {
	var privArr PrivKeyEd25519Arr
	if len(pwd) != 0 {
		pkBytes, err := libcrypto.Decrypt(privKey.encrypted, pwd)
		if err != nil {
			return err
		}
		copy(privArr[:], pkBytes)
	} else {
		if len(privKey.encrypted) != 64 {
			return errors.New("missing password")
		}
		copy(privArr[:], privKey.encrypted)
		privKey.encrypted = []byte{}
	}
	var err error
	// pkBytes will be wiped by memguard
	privKey.mg, err = memguard.NewImmutableFromBytes(privArr[:])
	libcrypto.WipeBytes(pwd)
	return err
}

func (privKey *PrivKeyEd25519) KeyBytes() []byte {
	arrPtr := privKey.arrayPtr()
	return (*arrPtr)[:]
}

func (privKey *PrivKeyEd25519) Bytes() []byte {
	return privKey.encrypted
}

// if init PrivKeyEd25519 in a wrong way,here would call a panic
func (privKey *PrivKeyEd25519) arrayPtr() *PrivKeyEd25519Arr {
	arr := (*PrivKeyEd25519Arr)(unsafe.Pointer(&privKey.mg.Buffer()[0]))
	return arr
}

func (privKey *PrivKeyEd25519) Sign(msg []byte) Signature {
	signatureBytes := ed25519.Sign(privKey.arrayPtr(), msg)
	bys := SignatureEd25519(*signatureBytes)
	return &bys
}

func (privKey *PrivKeyEd25519) PubKey() PubKey {
	pubkey := PubKeyEd25519(*ed25519.MakePublicKey(privKey.arrayPtr()))
	return &pubkey
}

func (privKey *PrivKeyEd25519) Equals(other PrivKey) bool {
	keyArrayPtr := privKey.arrayPtr()
	if otherEd, ok := other.(*PrivKeyEd25519); ok {
		otherArrayPtr := otherEd.arrayPtr()
		return bytes.Equal((*keyArrayPtr)[:], (*otherArrayPtr)[:])
	}
	return false
}

func (privKey *PrivKeyEd25519) ToCurve25519() *[32]byte {
	keyCurve25519 := new([32]byte)
	extra25519.PrivateKeyToCurve25519(keyCurve25519, privKey.arrayPtr())
	return keyCurve25519
}

func (privKey *PrivKeyEd25519) String() string {
	return Fmt("PrivKeyEd25519{*****}")
}

func (privKey *PrivKeyEd25519) MarshalJSON() ([]byte, error) {
	encBytes := privKey.encrypted
	if len(encBytes) == 0 {
		// not encrypted
		pkPtr := privKey.arrayPtr()
		encBytes = (*pkPtr)[:]
	}
	hstr := strings.ToUpper(hex.EncodeToString(encBytes))
	return json.Marshal([]interface{}{
		PrivKeyTypeEd25519, hstr,
	})
}

// after unmarshal, should call Decrypt() to init the key
func (privKey *PrivKeyEd25519) UnmarshalJSON(data []byte) error {
	var dec []interface{}
	err := json.Unmarshal(data, &dec)
	if err != nil {
		return err
	}
	if len(dec) < 2 {
		return errors.New("params missing when unmarshalJson PrivKeyTypeEd25519")
	}
	if byte(dec[0].(float64)) != PrivKeyTypeEd25519 {
		return errors.New("wrong marshal result for PrivKeyTypeEd25519")
	}
	hstr := dec[1].(string)
	privKey.encrypted, err = hex.DecodeString(hstr)
	return err
}

func (privKey *PrivKeyEd25519) Destroy() {
	privKey.mg.Destroy()
}

func GenPrivKeyEd25519(pwd []byte) (*PrivKeyEd25519, error) {
	var privKeyBytes PrivKeyEd25519Arr
	copy(privKeyBytes[:32], CRandBytes(32))
	ed25519.GenPublicKey(&privKeyBytes)
	privKey := &PrivKeyEd25519{}
	err := privKey.InitAndEncrypt(&privKeyBytes, pwd)
	if err != nil {
		privKey = nil
	}
	return privKey, err
}

// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyEd25519FromSecret(secret, pwd []byte) (*PrivKeyEd25519, error) {
	privKey32 := Sha256(secret) // Not Ripemd160 because we want 32 bytes.
	var privKeyBytes PrivKeyEd25519Arr
	copy(privKeyBytes[:32], privKey32)
	ed25519.GenPublicKey(&privKeyBytes)
	privKey := &PrivKeyEd25519{}
	err := privKey.InitAndEncrypt(&privKeyBytes, pwd)
	if err != nil {
		privKey = nil
	}
	return privKey, err
}

func EncryptSlcToEd25519(privKey, pwd []byte) (*PrivKeyEd25519, error) {
	var privArr PrivKeyEd25519Arr
	copy(privArr[:], privKey)
	libcrypto.WipeBytes(privKey)
	privKeyEd := &PrivKeyEd25519{}
	err := privKeyEd.InitAndEncrypt(&privArr, pwd)
	if err != nil {
		privKeyEd = nil
	}
	return privKeyEd, err
}

func DecryptSlcToEd25519(encrypted, pwd []byte) (*PrivKeyEd25519, error) {
	privKeyEd := &PrivKeyEd25519{}
	err := privKeyEd.InitAndDecrypt(encrypted, pwd)
	if err != nil {
		privKeyEd = nil
	}
	return privKeyEd, err
}

//-------------------------------------

type PrivKeySecp256k1Arr = [32]byte

// Implements PrivKey
type PrivKeySecp256k1 struct {
	//[32]byte
	encrypted []byte
	mg        *memguard.LockedBuffer
}

func (privKey *PrivKeySecp256k1) InitAndEncrypt(pkArr *PrivKeySecp256k1Arr, pwd []byte) error {
	var err error
	if len(pwd) != 0 {
		privKey.encrypted, err = libcrypto.Encrypt((*pkArr)[:], pwd)
		libcrypto.WipeBytes(pwd)
		if err != nil {
			return err
		}
	} else {
		privKey.encrypted = []byte{}
	}
	// pkBytes will be wiped by memguard
	if privKey.mg != nil && !privKey.mg.IsDestroyed() {
		privKey.mg.Destroy()
	}
	privKey.mg, err = memguard.NewImmutableFromBytes((*pkArr)[:])
	return err
}

func (privKey *PrivKeySecp256k1) Decrypt(pwd []byte) error {
	pkBytes, err := libcrypto.Decrypt(privKey.encrypted, pwd)
	if err != nil {
		return err
	}
	var pkArr PrivKeySecp256k1Arr
	copy(pkArr[:], pkBytes)
	// pkBytes will be wiped by memguard
	privKey.mg, err = memguard.NewImmutableFromBytes(pkArr[:])
	libcrypto.WipeBytes(pwd)
	return err
}

func (privKey *PrivKeySecp256k1) arrayPtr() *PrivKeySecp256k1Arr {
	return (*PrivKeySecp256k1Arr)(unsafe.Pointer(&privKey.mg.Buffer()[0]))
}

func (privKey *PrivKeySecp256k1) Sign(msg []byte) Signature {
	keyArrayPtr := privKey.arrayPtr()
	priv__, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), (*keyArrayPtr)[:])
	sig__, err := priv__.Sign(Sha256(msg))
	if err != nil {
		PanicSanity(err)
	}
	bys := SignatureSecp256k1(sig__.Serialize())
	return &bys
}

func (privKey *PrivKeySecp256k1) PubKey() PubKey {
	keyArrayPtr := privKey.arrayPtr()
	_, pub__ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), (*keyArrayPtr)[:])
	pub := [64]byte{}
	copy(pub[:], pub__.SerializeUncompressed()[1:])
	pubkey := PubKeySecp256k1(pub)
	return &pubkey
}

func (privKey *PrivKeySecp256k1) Equals(other PrivKey) bool {
	keyArrayPtr := privKey.arrayPtr()
	if otherSecp, ok := other.(*PrivKeySecp256k1); ok {
		otherArrayPtr := otherSecp.arrayPtr()
		return bytes.Equal((*keyArrayPtr)[:], (*otherArrayPtr)[:])
	}
	return false
}

func (privKey *PrivKeySecp256k1) String() string {
	return Fmt("PrivKeySecp256k1{*****}")
}

func (privKey *PrivKeySecp256k1) MarshalJSON() ([]byte, error) {
	hstr := strings.ToUpper(hex.EncodeToString(privKey.encrypted))
	return json.Marshal([]interface{}{
		PrivKeyTypeSecp256k1, hstr,
	})
}

func (privKey *PrivKeySecp256k1) UnmarshalJSON(data []byte) error {
	var dec []interface{}
	err := json.Unmarshal(data, &dec)
	if err != nil {
		return err
	}
	if len(dec) < 2 {
		return errors.New("params missing when unmarshalJson PrivKeyTypeSecp256k1")
	}
	if byte(dec[0].(float64)) != PrivKeyTypeSecp256k1 {
		return errors.New("wrong marshal result for PrivKeyTypeSecp256k1")
	}
	hstr := dec[1].(string)
	privKey.encrypted, err = hex.DecodeString(hstr)
	return err
}

func (privKey *PrivKeySecp256k1) Destroy() {
	privKey.mg.Destroy()
}

func GenPrivKeySecp256k1(pwd []byte) *PrivKeySecp256k1 {
	var privKeyBytes PrivKeySecp256k1Arr
	copy(privKeyBytes[:], CRandBytes(32))
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKeyBytes[:])
	copy(privKeyBytes[:], priv.Serialize())
	privKey := &PrivKeySecp256k1{}
	privKey.InitAndEncrypt(&privKeyBytes, pwd)
	return privKey
}

// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeySecp256k1FromSecret(secret, pwd []byte) *PrivKeySecp256k1 {
	privKey32 := Sha256(secret) // Not Ripemd160 because we want 32 bytes.
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey32)
	var privKeyBytes PrivKeySecp256k1Arr
	copy(privKeyBytes[:], priv.Serialize())
	privKey := &PrivKeySecp256k1{}
	privKey.InitAndEncrypt(&privKeyBytes, pwd)
	return privKey
}
