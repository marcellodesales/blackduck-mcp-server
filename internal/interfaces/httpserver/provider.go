package httpserver

import "net/http"

func ProvideHandler(r *Router) http.Handler {
	return r.Handler()
}
