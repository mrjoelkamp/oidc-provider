package op

import (
	"net/http"
)

// OIDC endpoints
// TODO: make these configurable
const (
	DiscoveryEndpoint     = "/.well-known/openid-configuration"
	AuthorizationEndpoint = "/authorize"
	TokenEndpoint         = "/token"
	JWKSEndpoint          = "/jwks.json"
)

// addRoutes adds all API routes to the provided mux
func addRoutes(
	mux *http.ServeMux,
	logger *Logger,
	op *OIDCProvider,
	storage *Storage,

) {
	mux.Handle("/", http.NotFoundHandler())
	mux.Handle(DiscoveryEndpoint, handleDiscovery(logger, op))
	mux.Handle(JWKSEndpoint, handleJWKS(logger, op))
	mux.Handle(AuthorizationEndpoint, handleAuthorization(logger, op, storage))
	mux.Handle(TokenEndpoint, handleToken(logger, op, storage))
}
