package op

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type ErrorCode string

// error codes as defined in https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1 and https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
var (
	ErrInvalidRequest          ErrorCode = "invalid_request"
	ErrUnauthorizedClient      ErrorCode = "unauthorized_client"
	ErrAccessDenied            ErrorCode = "access_denied"
	ErrUnsupportedResponseType ErrorCode = "unsupported_response_type"
	ErrInvalidScope            ErrorCode = "invalid_scope"
	ErrServerError             ErrorCode = "server_error"
	ErrTemporarilyUnavailable  ErrorCode = "temporarily_unavailable"
	ErrUnsupportedGrantType    ErrorCode = "unsupported_grant_type"
	ErrInvalidClient           ErrorCode = "invalid_client"
	ErrInvalidGrant            ErrorCode = "invalid_grant"
)

// error codes as defined in https://openid.net/specs/openid-connect-core-1_0.html#AuthError
var (
	ErrInteractionRequired      ErrorCode = "interaction_required"
	ErrLoginRequired            ErrorCode = "login_required"
	ErrAccountSelection         ErrorCode = "account_selection_required"
	ErrConsentRequired          ErrorCode = "consent_required"
	ErrInvalidRequestURI        ErrorCode = "invalid_request_uri"
	ErrInvalidRequestObject     ErrorCode = "invalid_request_object"
	ErrRequestNotSupported      ErrorCode = "request_not_supported"
	ErrRequestURINotSupported   ErrorCode = "request_uri_not_supported"
	ErrRegistrationNotSupported ErrorCode = "registration_not_supported"
)

// NewServer creates a new http.Handler by constructing an OIDC provider with the provided logger, config, and storage.
func NewServer(logger *Logger, config *Config, storage *Storage) http.Handler {
	mux := http.NewServeMux()

	// load keys from config path
	jwks, err := NewJWKS(config)
	if err != nil {
		logger.Error("failed to create JWKS", "error", err)
		os.Exit(1)
	}

	// create OIDC provider
	op := NewOIDCProvider(config.Issuer, jwks)

	// add routes
	addRoutes(mux, logger, op, storage)

	// setup middleware
	var handler http.Handler = mux
	handler = CORSHandler(handler)
	return handler
}

// TODO: make CORS configurable
func CORSHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length")
		h.ServeHTTP(w, r)
	})
}

// errorResponse writes an error response to the client
// https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
func errorResponse(w http.ResponseWriter, errorCode ErrorCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	response := &ErrorResponse{
		Error:            string(errorCode),
		ErrorDescription: desc,
	}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, ErrServerError)))
		return
	}
	w.Write(responseJSON)
}
