package playground

import (
	"net/http"
	"os"
)

func HomeHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		checkStartConfig()

		configMutex.Lock()
		tmplData := struct {
			Configured bool
			Title      string
			Config     Config
		}{
			Title:      "OAuth 2.0 Playground",
			Configured: config.ClientID != "" && config.ClientSecret != "",
			Config:     config,
		}
		configMutex.Unlock()

		writeTemplate(writer, "templates/index.gohtml", tmplData)
	})
}

func checkStartConfig() {
	authURI := os.Getenv("AUTHORIZATION_URI")
	tokenURI := os.Getenv("TOKEN_URI")
	userinfoURI := os.Getenv("USERINFO_URI")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	scopes := os.Getenv("SCOPES")
	if scopes == "" {
		// use some default-scopes
		scopes = "openid profile email"
	}

	if authURI != "" && tokenURI != "" && clientID != "" {
		configMutex.Lock()
		config.AuthorizationURI = authURI
		config.TokenURI = tokenURI
		config.UserinfoURI = userinfoURI
		config.ClientID = clientID
		config.ClientSecret = clientSecret
		config.Scopes = scopes
		configMutex.Unlock()
	}
}
