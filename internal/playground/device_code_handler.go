package playground

import "net/http"

func DeviceCodeHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "Not implemented", http.StatusNotImplemented)
	})
}
