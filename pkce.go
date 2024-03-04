package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
)

const (
	codeVerifierLength = 44
	pkceTitle          = "OAuth 2.0 Playground - PKCE Flow"
)

func pkceHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// generate a code-verifier and code-challenge
		codeVerifier, err := generateCodeVerifier(codeVerifierLength)
		if err != nil || codeVerifier == "" {
			http.Error(writer, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge := generateCodeChallenge(codeVerifier)

		// create new session and state
		state := generateRandomString(16)
		sessionsMutex.Lock()
		sessions[state] = &AuthSession{State: state, CodeVerifier: codeVerifier}
		sessionsMutex.Unlock()

		// Build the authorization URL
		configMutex.RLock()
		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {config.ClientID},
			"redirect_uri":          {"http://localhost:8080/auth/pkce/callback"},
			"state":                 {state},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"scope":                 {"openid profile email"},
		}
		authUrl := fmt.Sprintf("%s?%s", config.AuthorizationURI, params.Encode())
		configMutex.RUnlock()

		// render the HTML template
		tmplData := struct {
			Step         int
			Title        string
			AuthURL      string
			SessionToken string
		}{
			Step:         1,
			Title:        pkceTitle,
			AuthURL:      authUrl,
			SessionToken: state,
		}
		writeTemplate(writer, "html/pkce.gohtml", tmplData)
	})
}

func pkceCallbackHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// handle callback with the authorization code and state
		state := request.URL.Query().Get("state")

		sessionsMutex.RLock()
		session, exists := sessions[state]
		sessionsMutex.RUnlock()

		if !exists {
			http.Error(writer, "Invalid session token", http.StatusBadRequest)
			return
		}

		session.Code = request.URL.Query().Get("code")

		tmplData := struct {
			Step  int
			Title string
			State string
			Code  string
		}{
			Step:  2,
			Title: pkceTitle,
			State: state,
			Code:  session.Code,
		}

		writeTemplate(writer, "html/pkce.gohtml", tmplData)
	})
}

func pkceTokenHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Println("PKCE Token Handler")

		if err := request.ParseForm(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		sessionToken := request.PostFormValue("session_token")
		sessionsMutex.RLock()
		session, exists := sessions[sessionToken]
		sessionsMutex.RUnlock()

		if !exists || session.Code == "" {
			http.Error(writer, fmt.Sprintf("Invalid session token '%s' or code not found", sessionToken), http.StatusBadRequest)
			return
		}

		configMutex.RLock()
		tokenURI := config.TokenURI
		clientID := config.ClientID
		// with PKCE we do not have a client-secret! use the code-verifier instead
		configMutex.RUnlock()

		// get step
		step := request.PostFormValue("step")
		redirectUri := "http://localhost:8080/auth/pkce/callback"

		switch step {
		case "2":
			// show the token request parameters
			tmplData := struct {
				Step         int
				Title        string
				Code         string
				State        string
				ClientID     string
				RedirectURL  string
				TokenURL     string
				CodeVerifier string
			}{
				Step:         3,
				Title:        pkceTitle,
				Code:         session.Code,
				State:        sessionToken,
				ClientID:     clientID,
				RedirectURL:  redirectUri,
				TokenURL:     tokenURI,
				CodeVerifier: session.CodeVerifier,
			}

			fmt.Println("Showing PKCE Step 2")
			writeTemplate(writer, "html/pkce.gohtml", tmplData)
			return

		case "3":
			// exchange the authorization code for an access token
			tokenBytes, token, err := exchangeAccessToken(
				clientID,
				"",
				session.Code,
				redirectUri,
				tokenURI,
				session.CodeVerifier)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}

			// store the token in the session
			sessionsMutex.Lock()
			session.IDToken = token.IDToken
			session.AccessToken = token.AccessToken
			session.RefreshToken = token.RefreshToken
			sessionsMutex.Unlock()

			// display token response
			tmplData := struct {
				Step          int
				Title         string
				TokenResponse string
				SessionToken  string
				Token         *TokenResponse
			}{
				Step:          4,
				Title:         pkceTitle,
				TokenResponse: string(tokenBytes),
				SessionToken:  sessionToken,
				Token:         token,
			}

			fmt.Println("Showing PKCE Step 3")
			writeTemplate(writer, "html/pkce.gohtml", tmplData)
			return
		}

	})
}

// generateCodeVerifier creates a random string according to RVC 7336 PKCE, section 4.1
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
// To ensure that only ASCII-characters are used, we use a RawURLEncoding of the random string
// Allowing a maximum length of 128 characters and a min-length of 43 characters
func generateCodeVerifier(length int) (string, error) {
	// check min and max length according to RFC
	if length > 128 || length < 43 {
		return "", fmt.Errorf("codeVerifier length must be 43 <= length <= 128, got %d", length)
	}
	codeVerifier := make([]byte, 128)
	_, err := rand.Read(codeVerifier)
	if err != nil {
		return "", err
	}
	encodedString := base64.RawURLEncoding.EncodeToString(codeVerifier)
	if len(encodedString) > length {
		encodedString = encodedString[:length]
	}
	return encodedString, nil
}

// generateCodeChallenge creates a code-challenge from the code-verifier according to RVC 7336 PKCE, section 4.2
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
// if available, the code_verfier must use SHA256.
// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
func generateCodeChallenge(codeVerifier string) string {
	codeVerifierBytes := []byte(codeVerifier)
	codeChallengeBytes := sha256.Sum256(codeVerifierBytes)
	return base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])
}
