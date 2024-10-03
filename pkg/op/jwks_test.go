package op

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKS(t *testing.T) {
	// generate test keys
	jwks := generateTestJWKS(t)

	// create test server
	op := NewOIDCProvider(issuer, jwks)
	server := httptest.NewServer(handleJWKS(nil, op))
	defer server.Close()

	// test JWKS endpoint
	resp, err := http.Get(server.URL + JWKSEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// assert response equals public key jwks
	expected, err := json.Marshal(jwks.public)
	require.NoError(t, err)
	assert.Equal(t, expected, response)
}

func generateTestJWKS(t *testing.T) *JWKS {
	// generate test keys
	privateJWKS := jwk.NewSet()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privateKey, err := jwk.FromRaw(private)
	privateKey.Set(jwk.KeyIDKey, "private-key")
	privateKey.Set(jwk.AlgorithmKey, "ES256")
	privateKey.Set(jwk.KeyUsageKey, "sig")
	require.NoError(t, err)
	privateJWKS.AddKey(privateKey)
	publicJWKS := jwk.NewSet()
	publicKey, err := privateKey.PublicKey()
	require.NoError(t, err)
	publicJWKS.AddKey(publicKey)
	return &JWKS{private: privateJWKS, public: publicJWKS}
}
