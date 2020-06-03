package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"hash/fnv"
)

const (
	CPABE_PUBLIC_KEY = "public_key"
	CPABE_MASTER_KEY = "master_key"
)

type Behaviour struct {
	Id     string `json:"id"`
	Result bool   `json:"result"`
}

type OwnChaincode struct {
}

func (t *OwnChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	args := stub.GetStringArgs()
	if len(args) != 2 {
		return shim.Error("Should be 2 args")
	}
	pk, err := hex.DecodeString(args[0])
	if err != nil {
		return shim.Error("Fail to decode hex pk")
	}
	fmt.Println("Generating public key......")
	if err := stub.PutState(CPABE_PUBLIC_KEY, pk); err != nil {
		return shim.Error(err.Error())
	}
	sk, err := hex.DecodeString(args[1])
	if err != nil {
		return shim.Error("Fail to decode hex sk")
	}
	fmt.Println("Generating master key......")
	if err := stub.PutState(CPABE_MASTER_KEY, sk); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func (t *OwnChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	name, params := stub.GetFunctionAndParameters()
	switch name {
	case "beforeEncrypt":
		pk, err := t.beforeEncrypt(stub, params)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(pk)
	case "decrypt":
		data, err := t.decrypt(stub, params)
		if err != nil {
			//用空来判断，记录每一次下载尝试
			return shim.Success([]byte(""))
		}
		return shim.Success(data)
	case "appendTrans":
		err := t.appendTrans(stub, params)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success([]byte("success"))
	case "getAudit":
		data, err := t.getAudit(stub, params)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(data)
	default:
		return shim.Error("Not supported function")
	}
}

func (t *OwnChaincode) getAudit(stub shim.ChaincodeStubInterface, params []string) ([]byte, error) {
	if len(params) != 1 {
		return nil, errors.New("Need one file id")
	}
	data, _ := stub.GetState(params[0])
	return data, nil
}

func (t *OwnChaincode) beforeEncrypt(stub shim.ChaincodeStubInterface, params []string) ([]byte, error) {
	if len(params) < 3 {
		return nil, errors.New("Not sufficient parameters")
	}
	from_department_id := params[0]
	to_department_id := params[1]
	transaction_id := params[2]
	//check whether transaction exists
	transKey := fmt.Sprintf("trans_%s_%s_%s", from_department_id, to_department_id, transaction_id)
	tran, err := stub.GetState(transKey)
	if err != nil || tran == nil {
		return nil, errors.New("No such transaction")
	}
	data, err := stub.GetState(CPABE_PUBLIC_KEY)
	if err != nil || data == nil {
		return nil, errors.New("Fail to get public key")
	}
	hexpk := hex.EncodeToString(data)
	return []byte(hexpk), nil
}

func (t *OwnChaincode) decrypt(stub shim.ChaincodeStubInterface, params []string) ([]byte, error) {
	success := false
	if len(params) < 3 {
		return nil, errors.New("Not sufficient parameters")
	}
	text := params[0]
	//user id & file id
	fileId := params[1]
	userId := params[2]
	defer func() {
		data, _ := stub.GetState(fileId)
		var arr []Behaviour
		_ = json.Unmarshal(data, &arr)
		arr = append(arr, Behaviour{
			Id:     userId,
			Result: success,
		})
		data, err := json.Marshal(arr)
		if err != nil {
			return
		}
		_ = stub.PutState(fileId, data)
	}()
	attrs := params[3:]
	attrInt := make([]int, len(attrs))
	for k, v := range attrs {
		f := fnv.New32()
		f.Write([]byte(v))
		attrInt[k] = int(f.Sum32())
	}
	sk, err := getPrivateKey(stub)
	if err != nil {
		return nil, err
	}
	//keygen
	ak, err := Keygen(attrInt, sk)
	if err != nil {
		return nil, fmt.Errorf("Fail to generate key, %v", err)
	}
	//decrypt
	cipher, err := DecodeCipher(text)
	if err != nil {
		return nil, fmt.Errorf("Fail to get ciphertext, %v", err)
	}
	pk, err := getPublicKey(stub)
	if err != nil {
		return nil, err
	}
	str, err := Decrypt(cipher, ak, pk)
	if err != nil {
		return nil, fmt.Errorf("Fail to decrypt encrypted key, %v", err)
	}
	success = true
	return []byte(str), nil
}

func (t *OwnChaincode) appendTrans(stub shim.ChaincodeStubInterface, params []string) error {
	if len(params) < 3 {
		return errors.New("Not sufficient parameters")
	}
	from_department_id := params[0]
	to_department_id := params[1]
	transaction_id := params[2]
	key := fmt.Sprintf("trans_%s_%s_%s", from_department_id, to_department_id, transaction_id)
	if err := stub.PutState(key, []byte("yes")); err != nil {
		return errors.New("Fail to put tranaction state")
	}
	return nil
}

func getPublicKey(stub shim.ChaincodeStubInterface) (*abe.FAMEPubKey, error) {
	data, err := stub.GetState(CPABE_PUBLIC_KEY)
	if err != nil || data == nil {
		return nil, errors.New("Fail to get public key")
	}
	pk, err := DecodePubkey(data)
	if err != nil {
		return nil, errors.New("Fail to decode public key")
	}
	return pk, nil
}

func getPrivateKey(stub shim.ChaincodeStubInterface) (*abe.FAMESecKey, error) {
	data, err := stub.GetState(CPABE_MASTER_KEY)
	if err != nil || data == nil {
		return nil, errors.New("Fail to get master key")
	}
	sk, err := DecodePrikey(data)
	if err != nil {
		return nil, errors.New("Fail to decode master key")
	}
	return sk, nil
}

func main() {
	if err := shim.Start(&OwnChaincode{}); err != nil {
		fmt.Printf("Fatal error %v", err)
	}
}
