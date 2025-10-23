package auth

import (
	"encoding/json"
	"net/http"
	"time"
)

func RequestTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address   string `json:"address"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Verify signature
		ok, err := VerifySignature(req.Address, req.Message, req.Signature)
		if err != nil || !ok {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		token, err := GenerateToken(req.Address, time.Hour*1)
		if err != nil {
			http.Error(w, "failed to generate token", http.StatusInternalServerError)
			return
		}

		// Respond with the token
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token": token,
		})
	}
}
