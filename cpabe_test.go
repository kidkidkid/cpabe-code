package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"os"
	"testing"
)

func TestAA(t *testing.T) {
	//pubkey, prikey, _ := Setup()
	f, _ := os.Open("pk.txt")
	pkdata, _ := ioutil.ReadAll(f)
	f.Close()
	f, _ = os.Open("sk.txt")
	skdata, _ := ioutil.ReadAll(f)
	f.Close()
	pubkey := string(pkdata)
	prikey := string(skdata)
	pub, _ := hex.DecodeString(pubkey)
	pri, _ := hex.DecodeString(prikey)
	text := "sdnfsdfjsfjlsadflsdfdjsflksjdflkdsjfklsjfklsdjfklsdjflksjdkldsjs"
	attrs := []string{"depart_1000", "loc_212", "user_10000"}
	//encrypt
	//input: policy, text, attrs(verify necessity)
	pk, _ := DecodePubkey(pub)
	departAttr := "depart_1000"
	policy := fmt.Sprintf("%d", Hash(departAttr))
	ciphertext, _ := Encrypt(text, policy, pk)
	fmt.Println(ciphertext)
	//fmt.Println(ciphertext)
	//decrypt
	//input: attrs
	attrInt := make([]int, len(attrs))
	for k, v := range attrs {
		f := fnv.New32()
		f.Write([]byte(v))
		attrInt[k] = int(f.Sum32())
	}
	cp, _ := DecodeCipher(ciphertext)
	sk, _ := DecodePrikey(pri)
	ak, _ := Keygen(attrInt, sk)
	decryptedText, err := Decrypt(cp, ak, pk)
	fmt.Println(err, decryptedText)
}

func TestMM(t *testing.T) {
	var arr []Behaviour
	_ = json.Unmarshal(nil, &arr)
	arr =append(arr, Behaviour{
		Id:     "sadf",
		Result: false,
	})
	d, _ := json.Marshal(arr)
	fmt.Println(string(d))
}
