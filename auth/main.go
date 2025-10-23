package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// Secret key for signing JWTs (in production, store this securely)
var jwtSecret []byte

func Init(secret string) {
	jwtSecret = []byte(secret)
}

// Claims structure
type Claims struct {
	Address string `json:"address"`
	jwt.RegisteredClaims
}

// --------------------- SIGNATURE VERIFICATION ---------------------

// VerifySignature checks if the signature corresponds to the given address

func VerifySignature(address, message, signatureHex string) (bool, error) {
	sig, err := hex.DecodeString(strings.TrimPrefix(signatureHex, "0x"))
	if err != nil {
		return false, err
	}
	if len(sig) != 65 {
		return false, fmt.Errorf("invalid signature length: %d", len(sig))
	}

	// Normalize v value
	if sig[64] == 27 || sig[64] == 28 {
		sig[64] -= 27
	}

	prefixedMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := crypto.Keccak256Hash([]byte(prefixedMsg))

	fmt.Println("---- DEBUG VERIFY ----")
	fmt.Println("Address:", address)
	fmt.Println("Message:", message)
	fmt.Println("Signature:", signatureHex)
	fmt.Println("Prefixed message (with \\x19):", prefixedMsg)
	fmt.Println("Keccak256 Hash:", hex.EncodeToString(hash.Bytes()))
	fmt.Println("----------------------")

	pubKey, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return false, err
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey).Hex()
	fmt.Println("Recovered address:", recoveredAddr)
	return strings.EqualFold(recoveredAddr, address), nil
}

// --------------------- JWT GENERATION ---------------------

// GenerateToken generates a JWT for the given Ethereum address
func GenerateToken(address string, ttl time.Duration) (string, error) {
	claims := &Claims{
		Address: address,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   address,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// --------------------- JWT MIDDLEWARE ---------------------

// Middleware to protect endpoints
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := contextWithAddress(r.Context(), claims.Address)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// --------------------- CONTEXT HELPERS ---------------------

// GetAddressFromContext extracts Ethereum address from context
func GetAddressFromContext(r *http.Request) (string, error) {
	addr, ok := r.Context().Value(ctxKey{}).(string)
	if !ok || addr == "" {
		return "", errors.New("address not found in context")
	}
	return addr, nil
}

type ctxKey struct{}

func contextWithAddress(ctx context.Context, address string) context.Context {
	return context.WithValue(ctx, ctxKey{}, address)
}
