package op

import (
	"encoding/json"
	"net/http"
)

type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

func handleDiscovery(logger *Logger, op *OIDCProvider) http.HandlerFunc {
	discovery := &OIDCDiscovery{
		Issuer:                op.Issuer(),
		AuthorizationEndpoint: op.Issuer() + AuthorizationEndpoint,
		TokenEndpoint:         op.Issuer() + TokenEndpoint,
		JWKSURI:               op.Issuer() + JWKSEndpoint,
		ScopesSupported:       op.scopesSupported,
	}
	response, err := json.Marshal(discovery)
	if err != nil {
		logger.Error("failed to marshal discovery response", "error", err)
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
