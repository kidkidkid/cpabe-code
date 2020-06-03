package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"hash/fnv"
)

var fame *abe.FAME

func Setup() (hexpubkey, hexprikey string, err error) {
	hexprikey, hexpubkey, err = "", "", nil
	pub, pri, err := fame.GenerateMasterKeys()
	if err != nil {
		return
	}
	//encode public key
	buf := bytes.NewBuffer(nil)
	encoder := gob.NewEncoder(buf)
	err = encoder.Encode(pub)
	if err != nil {
		return
	}
	hexpubkey = hex.EncodeToString(buf.Bytes())
	//encode private key
	buf = bytes.NewBuffer(nil)
	encoder = gob.NewEncoder(buf)
	err = encoder.Encode(pri)
	if err != nil {
		return
	}
	hexprikey = hex.EncodeToString(buf.Bytes())
	return
}

func Keygen(attrs []int, prikey *abe.FAMESecKey) (*abe.FAMEAttribKeys, error) {
	key, err := fame.GenerateAttribKeys(attrs, prikey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func Decrypt(cipher *abe.FAMECipher, key *abe.FAMEAttribKeys, pk *abe.FAMEPubKey) (text string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	text, err = fame.Decrypt(cipher, key, pk)
	if err != nil {
		return
	}
	return
}

func Encrypt(text, policy string, pk *abe.FAMEPubKey) (string, error) {
	msp, err := abe.BooleanToMSP(policy, false)
	if err != nil {
		return "", err
	}
	cipher, err := fame.Encrypt(text, msp, pk)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil)
	encoder := gob.NewEncoder(buf)
	err = encoder.Encode(cipher)
	if err != nil {
		return "", err
	}
	hexkey := hex.EncodeToString(buf.Bytes())
	return hexkey, nil
}

func DecodePubkey(data []byte) (*abe.FAMEPubKey, error) {
	decoder := gob.NewDecoder(bytes.NewBuffer(data))
	pubkey := &abe.FAMEPubKey{}
	err := decoder.Decode(pubkey)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

func DecodePrikey(data []byte) (*abe.FAMESecKey, error) {
	decoder := gob.NewDecoder(bytes.NewBuffer(data))
	prikey := &abe.FAMESecKey{}
	err := decoder.Decode(prikey)
	if err != nil {
		return nil, err
	}
	return prikey, nil
}

func DecodeKey(key string) (*abe.FAMEAttribKeys, error) {
	data, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	decoder := gob.NewDecoder(bytes.NewBuffer(data))
	attrkey := &abe.FAMEAttribKeys{}
	err = decoder.Decode(attrkey)
	if err != nil {
		return nil, err
	}
	return attrkey, nil
}

func DecodeCipher(text string) (*abe.FAMECipher, error) {
	data, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}
	decoder := gob.NewDecoder(bytes.NewBuffer(data))
	cipher := &abe.FAMECipher{}
	err = decoder.Decode(cipher)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

func Hash(str string) int {
	f := fnv.New32()
	f.Write([]byte(str))
	return int(f.Sum32())
}

func init() {
	fame = abe.NewFAME()
}
