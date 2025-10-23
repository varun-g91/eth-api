package blockchain

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"
)

type UploadRequest struct {
	SignedTx string `json:"signedTx"`
}

type GetFileRequest struct {
	FileId string `json:"fileId"`
}

type FileData struct {
	IpfsHash         string
	FileName         string
	EncryptionMethod string
	Timestamp        *big.Int
}

// UploadHandler handles POST /upload to broadcast a signed tx
func UploadHandler(client *Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req UploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON request", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		receipt, err := client.BroadcastSignedTx(ctx, req.SignedTx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fileID, err := ExtractFileID(receipt, client.ContractABI)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("TxHash: %s\nFileId: %s", receipt.TxHash, fileID)

		resp := map[string]string{
			"fileId":          fileID,
			"transactionHash": receipt.TxHash.Hex(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// GetFileDataHandler handles retrieval of file metadata from the blockchain.
func GetFileDataHandler(client *Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fileIDHex := vars["fileId"]
		if fileIDHex == "" {
			http.Error(w, "fileId path parameter is required", http.StatusBadRequest)
			return
		}

		fileID := common.HexToHash(fileIDHex)
		log.Printf("[DEBUG] Calling getFileData with fileID: %s", fileID.Hex())

		// Use the GetFileData method instead of CallContract
		fileData, err := client.GetFileData(context.Background(), fileID)
		if err != nil {
			log.Printf("[ERROR] GetFileData failed: %v", err)
			http.Error(w, fmt.Sprintf("failed to retrieve file data: %v", err), http.StatusInternalServerError)
			return
		}

		// fileData is already a map[string]interface{} with the correct structure
		resp := map[string]interface{}{
			"ipfsHash":         fileData["ipfsHash"],
			"fileName":         fileData["fileName"],
			"encryptionMethod": fileData["encryptionMethod"],
			"timestamp":        fileData["timestamp"],
		}

		log.Printf("[DEBUG] File data retrieved: %+v", resp)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[ERROR] Failed to encode JSON response: %v", err)
		}
	}
}

// CallMethodHandler handles GET /callMethod/{methodName}
func CallMethodHandler(client *Client, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var out interface{}
		if _, err := client.CallContract(context.Background(), method, &out); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	}
}
