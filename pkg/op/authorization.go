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

func (a *AuthRequest) GetID() string {
	if a.state != "" {
		a.ID = a.state
	} else {
		a.ID = uuid.New().String()
	}
	return a.ID
}

func validateAuthRequest(r *AuthRequest, op *OIDCProvider) error {
	// validate request
	if r.responseType != "code" {
		return fmt.Errorf("unsupported response_type: %s", r.responseType)
	}
	if r.redirectURI == "" {
		return fmt.Errorf("missing redirect_uri")
	}

	// require code challenge if code challenge method is provided
	if r.codeChallenge != "" && r.codeChallengeMethod == "" {
		return fmt.Errorf("missing code_challenge_method")
	}

	// challenge method must be S256 or plain
	if r.codeChallengeMethod != "" && !slices.Contains(codeChallengeMethods, r.codeChallengeMethod) {
		return fmt.Errorf("unsupported code_challenge_method: %s", r.codeChallengeMethod)
	}

	// require OpenID scope
	if !slices.Contains(r.scope, "openid") {
		return fmt.Errorf("missing openid scope")
	}
	for _, scope := range r.scope {
		if !slices.Contains(op.scopesSupported, scope) {
			return fmt.Errorf("unsupported scope: %s", scope)
		}
	}

	// only support query response mode
	if r.responseMode != "" && r.responseMode != "query" {
		return fmt.Errorf("unsupported response_mode: %s", r.responseMode)
	}
	return nil
}

func parseAuthRequest(r *http.Request) *AuthRequest {
	return &AuthRequest{
		scope:               strings.Fields(r.FormValue("scope")),
		responseType:        r.FormValue("response_type"),
		clientID:            r.FormValue("client_id"),
		redirectURI:         r.FormValue("redirect_uri"),
		state:               r.FormValue("state"),
		nonce:               r.FormValue("nonce"),
		codeChallenge:       r.FormValue("code_challenge"),
		codeChallengeMethod: r.FormValue("code_challenge_method"),
		responseMode:        r.FormValue("response_mode"),
	}
}

func handleAuthorization(logger *Logger, op *OIDCProvider, storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// parse request
		authRequest := parseAuthRequest(r)
		err := validateAuthRequest(authRequest, op)
		if err != nil {
			logger.Error("failed to validate authorization request", "error", err)
			allowCORS(&w)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// store request
		storage.lock.Lock()
		storage.requests[authRequest.GetID()] = authRequest
		storage.lock.Unlock()

		// TODO authenticate end-user (not implemented)
		// TODO obtain consent from end-user (not implemented)

		// generate response
		code, err := Encrypt(authRequest.ID, op.codeEncryptionKey)
		if err != nil {
			logger.Error("failed to encrypt code", "error", err)
			allowCORS(&w)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// save code
		storage.lock.Lock()
		storage.codes[code] = &AuthCode{
			RequestID: authRequest.ID,
			Code:      code,
			Issued:    time.Now(),
		}
		storage.lock.Unlock()

		// write response
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := authResponse(authRequest, code)
		if err != nil {
			logger.Error("failed to generate response", "error", err)
			allowCORS(&w)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Info("authorization response", "uri", response)
		allowCORS(&w)
		http.Redirect(w, r, response, http.StatusFound)
	}
}

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
