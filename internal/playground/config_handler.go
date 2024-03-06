package playground

import "net/http"

func ConfigHandler() http.Handler {
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
