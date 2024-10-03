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

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// handleToken returns a handler that serves the token endpoint
func handleToken(logger *Logger, op *OIDCProvider, storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// parse request
		tokenRequest := parseTokenRequest(r)

		// validate request and verify auth code per https://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation
		err := validateTokenRequest(w, tokenRequest)
		if err != nil {
			logger.Error("failed to validate token request", "error", err)
			return
		}
		logger.Debug("token request", "request", tokenRequest)

		// verify authorization code
		err = verifyAuthCode(storage, tokenRequest, op.codeTimeout)
		if err != nil {
			errorResponse(w, ErrInvalidGrant, err.Error())
			logger.Error("failed to verify auth code", "error", err)
			return
		}

		// issue token
		token, err := createIDToken(op, logger)
		if err != nil {
			logger.Error("failed to create token", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// WARNING: logging of tokens is insecure and used for example purposes only
		logger.Debug("signed token", "token", token)

		// write response
		response := &TokenResponse{
			IDToken: token,
		}
		responseJSON, err := json.Marshal(response)
		if err != nil {
			logger.Error("failed to marshal response", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(responseJSON)
	}
}

func parseTokenRequest(r *http.Request) *TokenRequest {
	return &TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		CodeVerifier: r.FormValue("code_verifier"),
	}
}

// validateTokenRequest checks that the token request is well-formed
func validateTokenRequest(w http.ResponseWriter, r *TokenRequest) error {
	if r.GrantType != "authorization_code" {
		err := fmt.Errorf("unsupported grant_type: %s", r.GrantType)
		errorResponse(w, ErrUnsuppoertedGrantType, err.Error())
		return err
	}
	if r.Code == "" {
		err := fmt.Errorf("missing code")
		errorResponse(w, ErrInvalidRequest, err.Error())
		return err
	}
	if r.RedirectURI == "" {
		err := fmt.Errorf("missing redirect_uri")
		errorResponse(w, ErrInvalidRequest, err.Error())
		return err
	}
	return nil
}

// verifyAuthCode checks that the auth code is valid and hasn't expired
func verifyAuthCode(storage *Storage, r *TokenRequest, timeout int) error {
	// get auth challenge from storage
	storage.lock.Lock()
	defer storage.lock.Unlock()
	authCode, ok := storage.codes[r.Code]
	if !ok {
		return fmt.Errorf("unknown code")
	}
	// delete after use
	// TODO: with persistant storage and refresh tokens keep codes to detect reuse and revoke tokens
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
	// TODO: is PKCE required or is OP backwards compatible?
	//       if backwards compatible, handle requests with a code challenge but missing a code verifier
	if r.CodeVerifier != "" {
		err := verifyCodeChallenge(request, r.CodeVerifier)
		if err != nil {
			return err
		}
	}

	return nil
}

// verifyCodeChallenge checks that the code verifier matches the code challenge in the auth request
// https://www.rfc-editor.org/rfc/rfc7636.html#section-4.6
func verifyCodeChallenge(r *AuthRequest, verifier string) error {
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

// createIDToken generates a signed ID token for a single user
func createIDToken(op *OIDCProvider, logger *Logger) (string, error) {
	idt := jwt.New()
	idt.Set("iss", op.Issuer())
	idt.Set("sub", "test-user") // TODO: implement users

	// sign token
	key, err := op.PrivateKey()
	if err != nil {
		return "", err
	}
	token, err := SignToken(idt, key)
	if err != nil {
		return "", err
	}
	return token, nil
}
