package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

type AuthSession struct {
	State        string
	Code         string
	AccessToken  string
	IDToken      string
	RefreshToken string
}

var (
	sessions      = make(map[string]*AuthSession)
	sessionsMutex sync.RWMutex
)

func authCodeHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state := request.URL.Query().Get("state")
		if state == "" {
			// start a new session
			state = generateRandomString(16)

			sessionsMutex.Lock()
			sessions[state] = &AuthSession{State: state}
			sessionsMutex.Unlock()

			// Create authorization URL
			configMutex.RLock()
			authUrl := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&state=%s",
				config.AuthorizationURI,
				url.QueryEscape(config.ClientID),
				url.QueryEscape("http://localhost:8080/auth/code"),
				url.QueryEscape(state))
			configMutex.RUnlock()

			tmplData := struct {
				Step          int
				AuthURL       string
				SessionToken  string
				Authorization bool
			}{
				Step:         1,
				AuthURL:      authUrl,
				SessionToken: state,
			}

			writeTemplate(writer, "html/auth_code.html", tmplData)
			return
		}

		// handle callback with the authorization code and state
		sessionsMutex.RLock()
		session, exists := sessions[state]
		sessionsMutex.RUnlock()

		if !exists {
			http.Error(writer, "Invalid session token", http.StatusBadRequest)
			return
		}

		session.Code = request.URL.Query().Get("code")

		tmplData := struct {
			Step         int
			Code         string
			State        string
			SessionToken string
			Exchange     bool
		}{
			Step:         2,
			Code:         session.Code,
			State:        state,
			SessionToken: session.State,
		}

		writeTemplate(writer, "html/auth_code.html", tmplData)
	})
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func tokenHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
		clientSecret := config.ClientSecret
		configMutex.RUnlock()

		postData := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {session.Code},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
			"redirect_uri":  {"http://localhost:8080/auth/code"},
		}

		resp, err := http.PostForm(tokenURI, postData)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// read the response body
		tokenResponse, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		parsedToken, _ := parseTokenResponse(tokenResponse)

		sessionsMutex.Lock()
		session.IDToken = parsedToken.IDToken
		session.AccessToken = parsedToken.AccessToken
		session.RefreshToken = parsedToken.RefreshToken
		sessionsMutex.Unlock()

		// display the token response
		tmplData := struct {
			Step          int
			TokenResponse string
			SessionToken  string
			Token         *TokenResponse
		}{
			Step:          3,
			TokenResponse: string(tokenResponse),
			SessionToken:  session.State,
			Token:         parsedToken,
		}

		writeTemplate(writer, "html/auth_code.html", tmplData)
	})
}

func parseTokenResponse(response []byte) (*TokenResponse, error) {
	token := &TokenResponse{}
	if err := json.Unmarshal(response, token); err != nil {
		return nil, err
	}
	return token, nil
}

func userinfoHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
		userinfoURI := config.UserinfoURI
		configMutex.RUnlock()

		request, err := http.NewRequest("GET", userinfoURI, nil)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		// add the authorization
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session.AccessToken))

		// execute the userinfo request
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// read the response body
		userinfo, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		tmplData := struct {
			Step         int
			Userinfo     string
			SessionToken string
		}{
			Step:         4,
			Userinfo:     string(userinfo),
			SessionToken: session.State,
		}

		writeTemplate(writer, "html/auth_code.html", tmplData)
	})

}

func generateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}
