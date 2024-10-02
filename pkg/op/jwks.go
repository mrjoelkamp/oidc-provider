package op

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWKS struct {
	private jwk.Set
	public  jwk.Set
}

// TODO: support other key types besides EC256
// TODO: support for loading multiple keys
func loadKey(config *Config) (jwk.Key, error) {
	// Read the private key PEM file
	keyData, err := os.ReadFile(config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the EC private key using x509
	rawKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse EC private key: %v", err)
	}

	// Convert the EC private key into a JWK key
	key, err := jwk.FromRaw(rawKey)
	if err != nil {
		log.Fatalf("failed to convert EC private key to JWK: %v", err)
	}

	// Use the RFC 7638 method to set the key ID
	id, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		log.Fatalf("failed to generate key ID: %v", err)
	}
	b64ID := base64.RawURLEncoding.Strict().EncodeToString(id)
	key.Set("kid", b64ID)

	key.Set("alg", "ES256")
	key.Set("use", "sig")

	return key, nil
}

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

func handleJWKS(logger *Logger, op *OIDCProvider) http.HandlerFunc {
	response, err := op.jwks.MarshalJSON()
	if err != nil {
		logger.Error("failed to marshal JWKS", "error", err)
		return func(w http.ResponseWriter, r *http.Request) {
			allowCORS(&w)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		allowCORS(&w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(response)
	}
}
