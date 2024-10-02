package op

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
		codeTimeout:       10,
	}
}

func (o *OIDCProvider) Issuer() string {
	return o.issuer
}
