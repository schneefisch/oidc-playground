package playground

import (
	"html/template"
	"net/http"
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

func writeTemplate(writer http.ResponseWriter, templatePath string, data any) {
	baseTmpl, err := template.ParseFiles("templates/base.gohtml", templatePath)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	err = baseTmpl.ExecuteTemplate(writer, "base", data)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}
