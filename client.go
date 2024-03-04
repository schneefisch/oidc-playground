package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// exchangeAccessToken exchanges the authorization code for an access token
// Parameters:
// - clientId: the client ID
// - clientSecret: the client secret - required for Authorization Code Grant, leave empty for PKCE
// - code: the authorization code to be exchanged
// - redirectUri: the redirect URI for your application
// - tokenURI: the token endpoint
// - codeVerifier: the code verifier for PKCE - leave empty for Authorization Code Grant
// Returns:
// - the raw token response as byte array
// - the parsed token response with the standard fields
// - an error if the exchange failed
func exchangeAccessToken(clientId, clientSecret, code, redirectUri, tokenURI, codeVerifier string) ([]byte, *TokenResponse, error) {

	// create the request-payload
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectUri)

	// if clientSecret is provided, use the Authorization Code Grant
	if clientSecret != "" {
		data.Set("client_id", clientId)
		data.Set("client_secret", clientSecret)
	}

	// if codeVerifier is provided, use it for PKCE flow
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	fmt.Printf("sending data to tokenURI: %s\n%s", tokenURI, data)

	// create the request
	req, err := http.NewRequest("POST", tokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// IBM AppID requires the clientID and codeVerifier to be sent in the Authorization header as "Basic" auth
	if codeVerifier != "" {
		// ToDo: this is a quite specific implementation for IBM AppID provider. This should be made configurable via Environment-Variables or checkbox
		baseAuthHeader := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientId, codeVerifier)))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", baseAuthHeader))
	}

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// read the response body
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return rawBody, nil, err
	}

	// a 200 OK response status is expected. If not, return an error that contains the raw response body
	if resp.StatusCode != http.StatusOK {
		return rawBody, nil, fmt.Errorf("failed to exchange code for token with status: %d and body: %s", resp.StatusCode, rawBody)
	}

	var parsedToken TokenResponse
	err = json.Unmarshal(rawBody, &parsedToken)
	if err != nil {
		return rawBody, nil, err
	}

	return rawBody, &parsedToken, nil
}
