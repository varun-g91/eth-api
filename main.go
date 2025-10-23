package main

import (
	"eth_api_v2/auth"
	"eth_api_v2/blockchain"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

const (
	RouteUploadFile      = "/files"
	RouteGetFile         = "/files/{fileId}"
	RouteGetRequestToken = "/api/v1/request-tokens"
)

func main() {
	rpcURL := os.Getenv("BLOCKCHAIN_RPC_URL")
	contractAddr := os.Getenv("CONTRACT_ADDRESS")
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	abiPath := "./blockchain/FileStorageABI.json"

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super-strong-secret"
	}
	auth.Init(jwtSecret)

	// Blockchain client
	client := blockchain.NewClient(rpcURL, contractAddr, abiPath)

	// Router setup
	r := mux.NewRouter()

	// Public route (no middleware)
	if _, err := handleRoutes(RouteGetRequestToken, r, client); err != nil {
		log.Printf("Error registering public route: %v", err)
	}

	// Protected routes
	protected := r.PathPrefix("/api/v1").Subrouter()
	protected.Use(auth.Middleware)

	protectedRoutes := []string{RouteUploadFile, RouteGetFile}
	for _, route := range protectedRoutes {
		if _, err := handleRoutes(route, protected, client); err != nil {
			log.Printf("Error registering protected route %s: %v", route, err)
		}
	}

	log.Printf("Server running on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleRoutes(route string, r *mux.Router, client *blockchain.Client) (*mux.Route, error) {
	switch route {
	case RouteUploadFile:
		return r.HandleFunc(route, blockchain.UploadHandler(client)).Methods("POST"), nil
	case RouteGetFile:
		return r.HandleFunc(route, blockchain.GetFileDataHandler(client)).Methods("GET"), nil
	case RouteGetRequestToken:
		return r.HandleFunc(route, auth.RequestTokenHandler()).Methods("POST"), nil
	default:
		return nil, fmt.Errorf("Route not defined: %s", route)
	}
}
