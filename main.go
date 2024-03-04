package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
)

type Config struct {
	AuthorizationURI string
	TokenURI         string
	UserinfoURI      string
	ClientID         string
	ClientSecret     string
	Scopes           string
}

var (
	config      Config
	configMutex sync.RWMutex
)

func run() {
	http.Handle("GET /", homeHandler())
	http.Handle("POST /config", configHandler())
	http.Handle("GET /auth/code", authCodeHandler())
	http.Handle("POST /auth/code/token", tokenHandler())
	http.Handle("POST /auth/code/userinfo", userinfoHandler())
	http.Handle("GET /auth/pkce", pkceHandler())
	http.Handle("GET /auth/pkce/callback", pkceCallbackHandler())
	http.Handle("POST /auth/pkce/token", pkceTokenHandler())
	http.Handle("GET /auth/implicit", implicitHandler())
	http.Handle("GET /auth/device-code", deviceCodeHandler())
	http.Handle("GET /auth/oidc", oidcHandler())

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}

func main() {
	run()
}

func homeHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		checkStartConfig()

		configMutex.Lock()
		tmplData := struct {
			Configured bool
			Config     Config
		}{
			Configured: config.ClientID != "" && config.ClientSecret != "",
			Config:     config,
		}
		configMutex.Unlock()

		writeTemplate(writer, "html/index.gohtml", tmplData)
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

func configHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		configMutex.Lock()
		config.AuthorizationURI = request.PostFormValue("authorization_uri")
		config.TokenURI = request.PostFormValue("token_uri")
		config.UserinfoURI = request.PostFormValue("userinfo_uri")
		config.ClientID = request.PostFormValue("client_id")
		config.ClientSecret = request.PostFormValue("client_secret")
		configMutex.Unlock()

		// redirect back to home-page after saving the configuration
		http.Redirect(writer, request, "/", http.StatusSeeOther)
	})
}

func implicitHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "Not implemented", http.StatusNotImplemented)
	})
}

func deviceCodeHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "Not implemented", http.StatusNotImplemented)
	})
}

func oidcHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "Not implemented", http.StatusNotImplemented)
	})
}

func writeTemplate(writer http.ResponseWriter, templatePath string, data any) {
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(writer, data)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}
