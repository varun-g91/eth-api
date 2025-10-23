package blockchain

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Client struct {
	EthClient    *ethclient.Client
	ContractAddr common.Address
	ContractABI  abi.ABI
}

func NewClient(rpcURL, contractAddr, abiPath string) *Client {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum RPC: %v", err)
	}

	abiFile, err := os.ReadFile(filepath.Clean(abiPath))
	if err != nil {
		log.Fatalf("Failed to read ABI: %v", err)
	}

	parsedABI, err := abi.JSON(bytes.NewReader(abiFile))
	if err != nil {
		log.Fatalf("Failed to parse ABI: %v", err)
	}

	return &Client{
		EthClient:    client,
		ContractAddr: common.HexToAddress(contractAddr),
		ContractABI:  parsedABI,
	}
}

func (c *Client) BroadcastSignedTx(ctx context.Context, signedTxHex string) (*types.Receipt, error) {
	log.Printf("[DEBUG] BroadcastSignedTx called with signedTx: %s", signedTxHex[:20]+"...")

	txBytes, err := hex.DecodeString(signedTxHex[2:])
	if err != nil {
		log.Printf("[ERROR] Failed to decode signedTx: %v", err)
		return nil, err
	}

	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(txBytes); err != nil {
		log.Printf("[ERROR] Failed to unmarshal tx: %v", err)
		return nil, err
	}

	log.Printf("[DEBUG] Sending transaction to blockchain: %s", tx.Hash().Hex())
	if err := c.EthClient.SendTransaction(ctx, tx); err != nil {
		log.Printf("[ERROR] SendTransaction failed: %v", err)
		return nil, err
	}

	receipt, err := bind.WaitMined(ctx, c.EthClient, tx)
	if err != nil {
		log.Printf("[ERROR] WaitMined failed: %v", err)
		return nil, err
	}

	log.Printf("[DEBUG] Transaction mined. Receipt logs count: %d", len(receipt.Logs))
	return receipt, nil
}

func (c *Client) GetFileData(ctx context.Context, fileID common.Hash) (map[string]interface{}, error) {
	log.Printf("[DEBUG] GetFileData called with fileID: %s", fileID.Hex())

	data, err := c.ContractABI.Pack("getFileData", fileID)
	if err != nil {
		log.Printf("[ERROR] ABI pack failed: %v", err)
		return nil, err
	}

	msg := ethereum.CallMsg{To: &c.ContractAddr, Data: data}
	result, err := c.EthClient.CallContract(ctx, msg, nil)
	if err != nil {
		log.Printf("[ERROR] CallContract failed: %v", err)
		return nil, err
	}

	outputs, err := c.ContractABI.Unpack("getFileData", result)
	if err != nil {
		log.Printf("[ERROR] ABI unpack failed: %v", err)
		return nil, err
	}

	log.Printf("[DEBUG] ABI unpack output: %+v", outputs)

	if len(outputs) == 0 {
		return nil, fmt.Errorf("empty output from contract")
	}

	v := reflect.ValueOf(outputs[0])
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct output, got %v", v.Kind())
	}

	// Extract fields by name
	ipfsHash := v.FieldByName("IpfsHash")
	fileName := v.FieldByName("FileName")
	encryptionMethod := v.FieldByName("EncryptionMethod")
	timestamp := v.FieldByName("Timestamp")

	if !ipfsHash.IsValid() || !fileName.IsValid() || !encryptionMethod.IsValid() || !timestamp.IsValid() {
		return nil, fmt.Errorf("missing expected fields in struct")
	}

	dataMap := map[string]interface{}{
		"ipfsHash":         ipfsHash.String(),
		"fileName":         fileName.String(),
		"encryptionMethod": encryptionMethod.String(),
		"timestamp":        timestamp.Interface().(*big.Int).String(),
	}

	log.Printf("[DEBUG] Returning dataMap: %+v", dataMap)
	return dataMap, nil
}

func (c *Client) CallContract(ctx context.Context, methodName string, args ...interface{}) ([]interface{}, error) {
	data, err := c.ContractABI.Pack(methodName, args...)
	if err != nil {
		return nil, fmt.Errorf("ABI pack failed: %w", err)
	}

	msg := ethereum.CallMsg{To: &c.ContractAddr, Data: data}
	result, err := c.EthClient.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("contract call failed: %w", err)
	}

	outputs, err := c.ContractABI.Unpack(methodName, result)
	if err != nil {
		return nil, fmt.Errorf("ABI unpack failed: %w", err)
	}

	log.Printf("[DEBUG] Raw outputs from %s: %+v", methodName, outputs)
	return outputs, nil
}

func ExtractFileID(receipt *types.Receipt, contractABI abi.ABI) (string, error) {
	fileUploadedSig := []byte("FileUploaded(address,bytes32,string,string,uint256)")
	eventSigHash := crypto.Keccak256Hash(fileUploadedSig)

	for _, vLog := range receipt.Logs {
		if len(vLog.Topics) == 0 {
			continue
		}

		// Match event by its signature hash
		if vLog.Topics[0] == eventSigHash {
			// Decode non-indexed fields from data
			var decoded struct {
				IpfsHash         string
				EncryptionMethod string
				Timestamp        *big.Int
			}

			if err := contractABI.UnpackIntoInterface(&decoded, "FileUploaded", vLog.Data); err != nil {
				return "", fmt.Errorf("failed to unpack log data: %v", err)
			}

			// Indexed parameters are in Topics
			user := common.BytesToAddress(vLog.Topics[1].Bytes())
			fileID := vLog.Topics[2]

			fmt.Printf(
				"Event decoded:\nUser: %s\nFileID: %s\nIPFS: %s\nEncMethod: %s\nTime: %s\n",
				user.Hex(),
				fileID.Hex(),
				decoded.IpfsHash,
				decoded.EncryptionMethod,
				decoded.Timestamp.String(),
			)

			return fileID.Hex(), nil
		}
	}

	return "", fmt.Errorf("FileUploaded event not found in logs")
}
