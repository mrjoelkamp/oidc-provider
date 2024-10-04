package op

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthRequest(t *testing.T) {
	//create test server
	storage := newTestStorage(t)
	logger := newTestLogger(t)
	jwks := generateTestJWKS(t)
	op := NewOIDCProvider(issuer, jwks)
	testServer := httptest.NewServer(handleAuthorization(logger, op, storage))
	defer testServer.Close()

	testcases := []struct {
		name    string
		body    url.Values
		pass    bool
		failure ErrorCode
	}{
		{
			name: "valid request",
			body: url.Values{
				"scope":                 {"openid"},
				"response_type":         {"code"},
				"redirect_uri":          {"http://test.com"},
				"state":                 {"test-state"},
				"nonce":                 {"test-nonce"},
				"response_mode":         {"query"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
			},
			pass: true,
		},
		{
			name: "valid request (no PKCE)",
			body: url.Values{
				"scope":         {"openid"},
				"response_type": {"code"},
				"redirect_uri":  {"http://test.com"},
				"state":         {"test-state"},
				"nonce":         {"test-nonce"},
				"response_mode": {"query"},
			},
			pass: true,
		},
		{
			name:    "empty request",
			body:    url.Values{},
			failure: ErrInvalidRequest,
		},
		{
			name: "missing redirect uri",
			body: url.Values{
				"scope":                 {"openid"},
				"response_type":         {"code"},
				"state":                 {"test-state"},
				"nonce":                 {"test-nonce"},
				"response_mode":         {"query"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
			},
			failure: ErrInvalidRequest,
		},
		{
			name: "missing openid scope",
			body: url.Values{
				"scope":                 {""},
				"response_type":         {"code"},
				"redirect_uri":          {"http://test.com"},
				"state":                 {"test-state"},
				"nonce":                 {"test-nonce"},
				"response_mode":         {"query"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
			},
			failure: ErrInvalidScope,
		},
		{
			name: "unsupported scope",
			body: url.Values{
				"scope":                 {"profile"},
				"response_type":         {"code"},
				"redirect_uri":          {"http://test.com"},
				"state":                 {"test-state"},
				"nonce":                 {"test-nonce"},
				"response_mode":         {"query"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
			},
			failure: ErrInvalidScope,
		},
		{
			name: "unsupported response mode",
			body: url.Values{
				"scope":                 {"openid"},
				"response_type":         {"code"},
				"redirect_uri":          {"http://test.com"},
				"state":                 {"test-state"},
				"nonce":                 {"test-nonce"},
				"response_mode":         {"fragment"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
			},
			failure: ErrInvalidRequest,
		},
		{
			name: "unsupported response type",
			body: url.Values{
				"scope":                 {"openid"},
				"response_type":         {"token"},
				"redirect_uri":          {"http://test.com"},
				"state":                 {"test-state"},
				"nonce":                 {"test-nonce"},
				"response_mode":         {"query"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
			},
			failure: ErrUnsupportedResponseType,
		},
		{
			name: "missing code challenge",
			body: url.Values{
				"scope":                 {"openid"},
				"response_type":         {"code"},
				"redirect_uri":          {"http://test.com"},
				"state":                 {"test-state"},
				"nonce":                 {"test-nonce"},
				"response_mode":         {"query"},
				"code_challenge_method": {"S256"},
			},
			failure: ErrInvalidRequest,
		},
		{
			name: "unsupported code challenge method",
			body: url.Values{
				"scope":                 {"openid"},
				"response_type":         {"code"},
				"redirect_uri":          {"http://test.com"},
				"state":                 {"test-state"},
				"nonce":                 {"test-nonce"},
				"response_mode":         {"query"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"fail"},
			},
			failure: ErrInvalidRequest,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// must support both POST and GET requests https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// form post request
			post, err := client.PostForm(testServer.URL+AuthorizationEndpoint, tc.body)
			require.NoError(t, err)
			defer post.Body.Close()
			if post.StatusCode != http.StatusFound {
				assert.Equal(t, http.StatusBadRequest, post.StatusCode)
			} else {
				require.Equal(t, http.StatusFound, post.StatusCode)
				uri, err := url.Parse(post.Header.Get("Location"))
				require.NoError(t, err)
				params := uri.Query()
				if tc.pass {
					assert.NotEqual(t, params.Get("code"), "")
					assert.Equal(t, params.Get("state"), "test-state")
				} else {
					assert.Equal(t, params.Get("error"), string(tc.failure))
				}
			}

			// get query request
			url, err := url.Parse(testServer.URL + AuthorizationEndpoint)
			require.NoError(t, err)
			url.RawQuery = tc.body.Encode()
			get, err := client.Get(url.String())
			require.NoError(t, err)
			defer get.Body.Close()
			if get.StatusCode != http.StatusFound {
				assert.Equal(t, http.StatusBadRequest, get.StatusCode)
			} else {
				require.Equal(t, http.StatusFound, get.StatusCode)
				uri, err := url.Parse(get.Header.Get("Location"))
				require.NoError(t, err)
				params := uri.Query()
				if tc.pass {
					assert.NotEqual(t, params.Get("code"), "")
					assert.Equal(t, params.Get("state"), "test-state")
				} else {
					assert.Equal(t, params.Get("error"), string(tc.failure))
				}
			}
		})
	}
}
