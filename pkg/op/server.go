package op

import (
	"net/http"
	"os"
)

// TODO: make CORS configurable
func allowCORS(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")
}

func NewServer(logger *Logger, config *Config, storage *Storage) http.Handler {
	mux := http.NewServeMux()
	jwks, err := NewJWKS(config)
	if err != nil {
		logger.Error("failed to create JWKS", "error", err)
		os.Exit(1)
	}
	op := NewOIDCProvider(config.Issuer, jwks)

	addRoutes(mux, logger, op, storage)

	return mux
}
