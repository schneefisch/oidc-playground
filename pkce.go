package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func pkceHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// generate a code-verifier and code-challenge
		codeVerifier, err := generateCodeVerifier()
		if err != nil {
			http.Error(writer, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge, err := generateCodeChallenge(codeVerifier)
		if err != nil {
			http.Error(writer, "Failed to generate code challenge", http.StatusInternalServerError)
			return
		}

		// create new session and state
		state := generateRandomString(16)
		sessionsMutex.Lock()
		sessions[state] = &AuthSession{State: state, CodeVerifier: codeVerifier}
		sessionsMutex.Unlock()

		// Build the authorization URL
		configMutex.RLock()
		authUrl := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
			config.AuthorizationURI,
			url.QueryEscape(config.ClientID),
			url.QueryEscape("http://localhost:8080/auth/pkce/callback"),
			url.QueryEscape(state),
			url.QueryEscape(codeChallenge))
		configMutex.RUnlock()

		// render the HTML template
		tmplData := struct {
			Step         int
			AuthURL      string
			SessionToken string
		}{
			Step:         1,
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
			State string
			Code  string
		}{
			Step:  2,
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
				Code         string
				State        string
				ClientID     string
				RedirectURL  string
				TokenURL     string
				CodeVerifier string
			}{
				Step:         3,
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
			tokenBytes, token, err := exchangeAccessToken(clientID, "", session.Code, redirectUri, tokenURI, session.CodeVerifier)
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
				TokenResponse string
				SessionToken  string
				Token         *TokenResponse
			}{
				Step:          4,
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

func exchangeAccessToken(clientId string, clientSecret string, code string, redirectUri string, tokenURI string, codeVerifier string) ([]byte, *TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientId)
	if clientSecret != "" {
		// if clientSecret is provided, use the Authorization Code Grant
		data.Set("client_secret", clientSecret)
	} else {
		// No client-secret means, we have the PKCE flow and must use a code-challenge
		// ToDo: probably needs the code-challenge too.
		data.Set("code_verifier", codeVerifier)
	}
	data.Set("code", code)
	data.Set("redirect_uri", redirectUri)

	req, err := http.NewRequest(http.MethodPost, tokenURI, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = data

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	tokenResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to exchange code for token: %s", tokenResponse)
	}

	var parsedToken TokenResponse
	err = json.Unmarshal(tokenResponse, &parsedToken)
	if err != nil {
		return nil, nil, err
	}

	return tokenResponse, &parsedToken, nil
}

func generateCodeVerifier() (string, error) {
	codeVerifier := make([]byte, 64)
	_, err := rand.Read(codeVerifier)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(codeVerifier), nil
}

func generateCodeChallenge(codeVerifier string) (string, error) {
	codeVerifierBytes := []byte(codeVerifier)
	codeChallengeBytes := sha256.Sum256(codeVerifierBytes)
	return base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:]), nil
}
