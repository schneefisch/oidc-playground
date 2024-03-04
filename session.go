package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

type AuthSession struct {
	State        string
	Code         string
	AccessToken  string
	IDToken      string
	RefreshToken string
	CodeVerifier string
}

var sessions = make(map[string]*AuthSession)

var sessionsMutex sync.RWMutex

func generateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}
