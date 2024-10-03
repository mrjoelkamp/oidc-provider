package op

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Encrypt encrypts data using the given key and returns the base64 encoded ciphertext
func Encrypt(data string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plaintext := []byte(data)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return base64.RawURLEncoding.Strict().EncodeToString(ciphertext), nil
}

// SignToken signs a token using the given key and returns a compact jwt string
func SignToken(token jwt.Token, key jwk.Key) (string, error) {
	signed, err := jwt.Sign(token, jwt.WithKey(key.Algorithm(), key)) // TODO: support other algorithms
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return string(signed), nil
}

// loadKey reads the private key from the file system and converts it into a JWK key
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
