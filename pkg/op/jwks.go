package op

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWKS struct {
	private jwk.Set
	public  jwk.Set
}

// handleJWKS returns a handler that serves the JWKS endpoint
func handleJWKS(logger *Logger, op *OIDCProvider) http.HandlerFunc {
	response, err := op.jwks.MarshalJSON()
	if err != nil {
		logger.Error("failed to marshal JWKS", "error", err)
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(response)
	}
}

// NewJWKS creates a new JWKS instance with a private and public key set
func NewJWKS(config *Config) (*JWKS, error) {
	key, err := loadKey(config)
	if err != nil {
		return nil, err
	}
	private := jwk.NewSet()
	private.AddKey(key)

	public := jwk.NewSet()
	pubKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %w", err)
	}
	public.AddKey(pubKey)
	return &JWKS{private: private, public: public}, nil
}

func (k *JWKS) GetPrivateKeySet(config *Config) jwk.Set {
	return k.private
}

func (k *JWKS) GetPublicKeySet(config *Config) jwk.Set {
	return k.public
}

func (k *JWKS) MarshalJSON() ([]byte, error) {
	buf, err := json.Marshal(k.public)
	if err != nil {
		log.Fatalf("failed to marshal JWKS: %v", err)
	}
	return buf, nil
}
