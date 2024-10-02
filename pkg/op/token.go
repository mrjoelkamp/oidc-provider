package op

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
}

type TokenResponse struct {
	IDToken string `json:"id_token"`
}

type IDTokenClaims struct {
	Issuer string `json:"iss"`
	Sub    string `json:"sub"`
}

func createIDToken(op *OIDCProvider, logger *Logger) (string, error) {
	idt := jwt.New()
	idt.Set("iss", op.Issuer())
	idt.Set("sub", "test-user") // TODO: implement users

	// sign token
	key, ok := op.jwks.private.Key(0) // TODO: support multiple keys
	if !ok {
		return "", fmt.Errorf("failed to get private key")
	}
	signed, err := jwt.Sign(idt, jwt.WithKey(key.Algorithm(), key)) // TODO: support other algorithms
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return string(signed), nil
}

func parseTokenRequest(r *http.Request) *TokenRequest {
	return &TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		CodeVerifier: r.FormValue("code_verifier"),
	}
}

func validateTokenRequest(r *TokenRequest) error {
	if r.GrantType != "authorization_code" {
		return fmt.Errorf("unsupported grant_type: %s", r.GrantType)
	}
	if r.Code == "" {
		return fmt.Errorf("missing code")
	}
	if r.RedirectURI == "" {
		return fmt.Errorf("missing redirect_uri")
	}
	return nil
}

func verifyAuthCode(storage *Storage, r *TokenRequest, timeout int) error {
	// get auth challenge from storage
	storage.lock.Lock()
	defer storage.lock.Unlock()
	authCode, ok := storage.codes[r.Code]
	if !ok {
		return fmt.Errorf("unknown code")
	}
	defer delete(storage.codes, r.Code)

	// check that the code hasn't expired
	if authCode.Issued.Add(time.Duration(timeout) * time.Minute).Before(time.Now()) {
		return fmt.Errorf("code expired")
	}

	// check that the redirect URI matches request
	request, ok := storage.requests[authCode.RequestID]
	if !ok {
		return fmt.Errorf("unknown request")
	}
	defer delete(storage.requests, request.GetID())
	if request.redirectURI != r.RedirectURI {
		return fmt.Errorf("invalid redirect URI")
	}

	// verify code challenge for PKCE
	if r.CodeVerifier != "" {
		err := verifyCodeChallenge(request, r.CodeVerifier, timeout)
		if err != nil {
			return err
		}
	}

	return nil
}

func verifyCodeChallenge(r *AuthRequest, verifier string, timeout int) error {
	switch r.codeChallengeMethod {
	case "plain", "":
		if r.codeChallenge != verifier {
			return fmt.Errorf("invalid code verifier")
		}
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.Strict().EncodeToString(hash[:])
		if challenge != r.codeChallenge {
			return fmt.Errorf("invalid code challenge")
		}
	default:
		return fmt.Errorf("unsupported code challenge method: %s", r.codeChallengeMethod)
	}
	return nil
}

func handleToken(logger *Logger, op *OIDCProvider, storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// parse request
		tokenRequest := parseTokenRequest(r)
		err := validateTokenRequest(tokenRequest)
		if err != nil {
			logger.Error("failed to validate token request", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// verify authorization code
		err = verifyAuthCode(storage, tokenRequest, op.codeTimeout)
		if err != nil {
			logger.Error("failed to verify auth code", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// issue token
		token, err := createIDToken(op, logger)
		if err != nil {
			logger.Error("failed to create token", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// write response
		response := &TokenResponse{
			IDToken: token,
		}
		logger.Info("signed token", "token", token)
		responseJSON, err := json.Marshal(response)
		if err != nil {
			logger.Error("failed to marshal response", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		allowCORS(&w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(responseJSON)
	}
}
