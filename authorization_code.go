package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	authCodeTitle = "OAuth 2.0 Playground - Authorization Code Flow"
)

func authCodeHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state := request.URL.Query().Get("state")
		if state == "" {
			// start a new session
			state = generateRandomString(16)
			nonce := generateRandomString(20)

			sessionsMutex.Lock()
			sessions[state] = &AuthSession{State: state, Nonce: nonce}
			sessionsMutex.Unlock()

			// Create authorization URL
			configMutex.RLock()
			queryParams := url.Values{
				"response_type": {"code"},
				"client_id":     {config.ClientID},
				"redirect_uri":  {"http://localhost:8080/auth/code"},
				"state":         {state},
				"nonce":         {nonce},
				"scope":         {config.Scopes},
			}
			authUrl := fmt.Sprintf("%s?%s", config.AuthorizationURI, queryParams.Encode())
			configMutex.RUnlock()

			tmplData := struct {
				Step          int
				Title         string
				AuthURL       string
				SessionToken  string
				Authorization bool
			}{
				Step:         1,
				Title:        authCodeTitle,
				AuthURL:      authUrl,
				SessionToken: state,
			}

			writeTemplate(writer, "html/auth_code.gohtml", tmplData)
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
		gotNonce := request.URL.Query().Get("nonce")

		tmplData := struct {
			Step         int
			Title        string
			Code         string
			State        string
			Nonce        string
			SessionToken string
		}{
			Step:         2,
			Title:        authCodeTitle,
			Code:         session.Code,
			State:        state,
			Nonce:        gotNonce,
			SessionToken: session.State,
		}

		writeTemplate(writer, "html/auth_code.gohtml", tmplData)
	})
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

		rawToken, parsedToken, err := exchangeAccessToken(clientID,
			clientSecret,
			session.Code,
			"http://localhost:8080/auth/code",
			tokenURI,
			"")
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		sessionsMutex.Lock()
		session.IDToken = parsedToken.IDToken
		session.AccessToken = parsedToken.AccessToken
		session.RefreshToken = parsedToken.RefreshToken
		sessionsMutex.Unlock()

		// display the token response
		tmplData := struct {
			Step          int
			Title         string
			TokenResponse string
			SessionToken  string
			Token         *TokenResponse
		}{
			Step:          3,
			Title:         authCodeTitle,
			TokenResponse: string(rawToken),
			SessionToken:  session.State,
			Token:         parsedToken,
		}

		writeTemplate(writer, "html/auth_code.gohtml", tmplData)
	})
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
			Title        string
			Userinfo     string
			SessionToken string
		}{
			Step:         4,
			Title:        authCodeTitle,
			Userinfo:     string(userinfo),
			SessionToken: session.State,
		}

		writeTemplate(writer, "html/auth_code.gohtml", tmplData)
	})
}
