package op

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

var (
	// only support openid scope for now
	scopes = []string{"openid"}

	// codeEncryptionKey is a secret key used to generate authorization codes
	codeEncryptionKey = []byte("this-is-a-secret")
)

type OIDCProvider struct {
	issuer            string
	jwks              *JWKS
	scopesSupported   []string
	codeEncryptionKey []byte
	codeTimeout       int
}

func NewOIDCProvider(issuer string, jwks *JWKS) *OIDCProvider {
	return &OIDCProvider{
		issuer:            issuer,
		jwks:              jwks,
		scopesSupported:   scopes,
		codeEncryptionKey: codeEncryptionKey[:],
		codeTimeout:       10, // TODO: make auth code timeout configurable
	}
}

func (o *OIDCProvider) Issuer() string {
	return o.issuer
}

func (o *OIDCProvider) PrivateKey() (jwk.Key, error) {
	key, ok := o.jwks.private.Key(0) // TODO: support multiple keys
	if !ok {
		return nil, fmt.Errorf("failed to get private key")
	}
	return key, nil
}
