package main

import (
	"github.com/schneefisch/oidc-playground/internal/playground"
	"log"
	"net/http"
)

func run() {
	http.Handle("GET /", playground.HomeHandler())
	http.Handle("POST /config", playground.ConfigHandler())
	http.Handle("GET /auth/code", playground.AuthCodeHandler())
	http.Handle("POST /auth/code/token", playground.TokenHandler())
	http.Handle("POST /auth/code/userinfo", playground.UserinfoHandler())
	http.Handle("GET /auth/pkce", playground.PkceHandler())
	http.Handle("GET /auth/pkce/callback", playground.PkceCallbackHandler())
	http.Handle("POST /auth/pkce/token", playground.PkceTokenHandler())
	http.Handle("GET /auth/device-code", playground.DeviceCodeHandler())
	http.Handle("GET /auth/oidc", playground.OidcHandler())

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}

func main() {
	run()
}
