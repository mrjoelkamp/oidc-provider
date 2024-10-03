package op

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	codeChallengeMethods = []string{"plain", "S256"}
)

type AuthRequest struct {
	ID                  string
	scope               []string
	responseType        string
	clientID            string // client_id is normally required, but not used by test suite
	redirectURI         string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	responseMode        string
}

// GetID returns the request ID, generating a new one if it doesn't exist
func (a *AuthRequest) GetID() string {
	if a.ID == "" {
		// generate a uuid if state doesn't exist and use it as the request ID
		if a.state != "" {
			a.ID = a.state
		} else {
			a.ID = uuid.New().String()
		}
	}
	return a.ID
}

// handleAuthorization returns a handler that serves the authorization endpoint
func handleAuthorization(logger *Logger, op *OIDCProvider, storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// parse request
		authRequest := parseAuthRequest(r)

		// validate request per https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation
		err := validateAuthRequest(w, r, authRequest, op)
		if err != nil {
			logger.Error("failed to validate authorization request", "error", err)
			return
		}
		logger.Debug("authorization request", "request", authRequest)

		// store request
		storage.lock.Lock()
		storage.requests[authRequest.GetID()] = authRequest
		storage.lock.Unlock()

		// TODO authenticate end-user (not implemented)
		// TODO obtain consent from end-user (not implemented)

		// generate response
		code, err := Encrypt(authRequest.GetID(), op.codeEncryptionKey)
		if err != nil {
			logger.Error("failed to encrypt code", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Debug("authorization code generated", "code", code)

		// save code
		storage.lock.Lock()
		storage.codes[code] = &AuthCode{
			RequestID: authRequest.GetID(),
			Code:      code,
			Issued:    time.Now(),
		}
		storage.lock.Unlock()

		// write response
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := authResponse(authRequest, code)
		if err != nil {
			logger.Error("failed to generate response", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Debug("authorization response", "uri", response)
		http.Redirect(w, r, response, http.StatusFound)
	}
}

func parseAuthRequest(r *http.Request) *AuthRequest {
	return &AuthRequest{
		scope:               strings.Fields(r.FormValue("scope")),
		responseType:        r.FormValue("response_type"),
		clientID:            r.FormValue("client_id"), // client_id is normally required, but not used in this exercise
		redirectURI:         r.FormValue("redirect_uri"),
		state:               r.FormValue("state"),
		nonce:               r.FormValue("nonce"), // TODO: nonce saved but not currently included in token claims
		codeChallenge:       r.FormValue("code_challenge"),
		codeChallengeMethod: r.FormValue("code_challenge_method"),
		responseMode:        r.FormValue("response_mode"),
	}
}

// validateAuthRequest checks that the authorization request is well-formed
func validateAuthRequest(w http.ResponseWriter, r *http.Request, authReq *AuthRequest, op *OIDCProvider) error {
	// note: client_id is typically required, but not used in this exercise

	// TODO: add client redirection URI registration and check that it matches
	if authReq.redirectURI == "" {
		// use errorResponse here to return a 400 response and not follow the missing redirect URI
		// https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1
		err := fmt.Errorf("missing redirect_uri")
		errorResponse(w, ErrInvalidRequest, err.Error())
		return err
	}

	// validate request
	if authReq.responseType != "code" {
		err := fmt.Errorf("unsupported response_type: %s", authReq.responseType)
		authErrorResponse(w, r, authReq, ErrUnsupportedResponseType, err.Error())
		return err
	}

	// require code challenge if code challenge method is provided
	if authReq.codeChallenge != "" && authReq.codeChallengeMethod == "" {
		err := fmt.Errorf("missing code_challenge_method")
		authErrorResponse(w, r, authReq, ErrInvalidRequest, err.Error())
		return err
	}

	// challenge method must be S256 or plain
	if authReq.codeChallengeMethod != "" && !slices.Contains(codeChallengeMethods, authReq.codeChallengeMethod) {
		err := fmt.Errorf("unsupported code_challenge_method: %s", authReq.codeChallengeMethod)
		authErrorResponse(w, r, authReq, ErrInvalidRequest, err.Error())
		return err
	}

	// require OpenID scope
	if !slices.Contains(authReq.scope, "openid") {
		err := fmt.Errorf("missing openid scope")
		authErrorResponse(w, r, authReq, ErrInvalidScope, err.Error())
		return err
	}
	for _, scope := range authReq.scope {
		if !slices.Contains(op.scopesSupported, scope) {
			err := fmt.Errorf("unsupported scope: %s", scope)
			authErrorResponse(w, r, authReq, ErrInvalidScope, err.Error())
			return err
		}
	}

	// only support query response mode
	if authReq.responseMode != "" && authReq.responseMode != "query" {
		// return 400 for unsupported response types https://openid.net/specs/openid-connect-core-1_0.html#AuthError
		err := fmt.Errorf("unsupported response_mode: %s", authReq.responseMode)
		authErrorResponse(w, r, authReq, ErrInvalidRequest, err.Error())
		return err
	}
	return nil
}

// authResponse generates an authorization response URI
func authResponse(r *AuthRequest, code string) (string, error) {
	uri, err := url.Parse(r.redirectURI)
	if err != nil {
		return "", err
	}
	params := uri.Query()
	params.Add("code", code)
	if r.state != "" {
		params.Add("state", r.state)
	}
	uri.RawQuery = params.Encode()
	return uri.String(), nil
}

// authErrorResponse generates an authorization error response URI as application/x-www-form-urlencoded
func authErrorResponse(w http.ResponseWriter, r *http.Request, authRequest *AuthRequest, errorCode ErrorCode, desc string) error {
	uri, err := url.Parse(authRequest.redirectURI)
	if err != nil {
		return err
	}
	params := uri.Query()
	params.Add("error", string(errorCode))
	// state is required per https://www.rfc-editor.org/rfc/rfc6749.html#section-4.2.2.1
	if authRequest.state != "" {
		params.Add("state", authRequest.state)
	}
	if desc != "" {
		params.Add("error_description", desc)
	}
	uri.RawQuery = params.Encode()
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	http.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}
