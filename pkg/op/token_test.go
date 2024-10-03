package op

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRequest(t *testing.T) {
	testcases := []struct {
		name    string
		body    url.Values
		pass    bool
		failure ErrorCode
	}{
		{
			name: "valid request",
			body: url.Values{
				"grant_type":    {"authorization_code"},
				"redirect_uri":  {"http://test.com"},
				"code":          {"test-code"},
				"code_verifier": {"test-challenge"},
			},
			pass: true,
		},
		{
			name:    "empty request",
			body:    url.Values{},
			failure: ErrInvalidRequest,
		},
		{
			name: "missing grant type",
			body: url.Values{
				"redirect_uri":  {"http://test.com"},
				"code":          {"test-code"},
				"code_verifier": {"test-challenge"},
			},
			failure: ErrUnsupportedGrantType,
		},
		{
			name: "invalid grant type",
			body: url.Values{
				"grant_type":    {"client_credentials"},
				"redirect_uri":  {"http://test.com"},
				"code":          {"test-code"},
				"code_verifier": {"test-challenge"},
			},
			failure: ErrUnsupportedGrantType,
		},
		{
			name: "missing redirect uri",
			body: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"test-code"},
				"code_verifier": {"test-challenge"},
			},
			failure: ErrInvalidRequest,
		},
		{
			name: "invalid redirect uri",
			body: url.Values{
				"grant_type":    {"authorization_code"},
				"redirect_uri":  {"http://fail.com"},
				"code":          {"test-code"},
				"code_verifier": {"test-challenge"},
			},
			failure: ErrInvalidRequest,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			//create test server
			storage := newTestStorage(t)
			logger := newTestLogger(t)
			jwks := generateTestJWKS(t)
			op := NewOIDCProvider(issuer, jwks)
			testServer := httptest.NewServer(handleToken(logger, op, storage))

			// send request
			resp, err := http.PostForm(testServer.URL+TokenEndpoint, tc.body)
			require.NoError(t, err)
			defer resp.Body.Close()
			if tc.pass {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				respone := &TokenResponse{}
				err = json.NewDecoder(resp.Body).Decode(respone)
				require.NoError(t, err)
				assert.NotEmpty(t, respone.IDToken)
				storage = newTestStorage(t)
			} else {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
				errorResponse := &ErrorResponse{}
				err = json.NewDecoder(resp.Body).Decode(errorResponse)
				require.NoError(t, err)
				assert.Equal(t, string(tc.failure), errorResponse.Error)
			}

			// close test server
			testServer.Close()
		})
	}
}

func newTestStorage(t *testing.T) *Storage {
	// test request
	testRequest := &AuthRequest{
		ID:                  "test-request",
		redirectURI:         "http://test.com",
		codeChallenge:       "test-challenge",
		codeChallengeMethod: "plain",
	}
	// test code
	testCode := &AuthCode{
		RequestID: testRequest.GetID(),
		Code:      "test-code",
		Issued:    time.Now(),
	}
	storage := NewStorage()
	storage.requests[testRequest.GetID()] = testRequest
	storage.codes[testCode.Code] = testCode
	return storage
}

func newTestLogger(t *testing.T) *Logger {
	config := &Config{LogLevel: "error"}
	logger := NewLogger(config)
	return logger
}
