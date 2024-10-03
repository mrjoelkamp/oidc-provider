package op

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	issuer = "http://op.test.com"
)

func TestDiscovery(t *testing.T) {
	// create test server
	op := NewOIDCProvider(issuer, nil)
	testServer := httptest.NewServer(handleDiscovery(nil, op))
	defer testServer.Close()

	// test discovery endpoint
	resp, err := http.Get(testServer.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	payload := &OIDCDiscovery{}
	err = json.NewDecoder(resp.Body).Decode(payload)
	require.NoError(t, err)

	assert.Equal(t, payload.Issuer, issuer)
	assert.Equal(t, payload.AuthorizationEndpoint, issuer+AuthorizationEndpoint)
	assert.Equal(t, payload.TokenEndpoint, issuer+TokenEndpoint)
	assert.Equal(t, payload.JWKSURI, issuer+JWKSEndpoint)
	assert.Equal(t, payload.ScopesSupported, []string{"openid"})
}
