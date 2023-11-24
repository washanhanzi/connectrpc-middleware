package middleware

import (
	"net/http"
	"strings"

	"connectrpc.com/connect"
)

type authMiddleware struct {
	handler *AuthHandler
	errW    *connect.ErrorWriter
}

func NewAuthMiddleware(handler *AuthHandler) *authMiddleware {
	return &authMiddleware{
		handler: handler,
		//TODO opts
		errW: connect.NewErrorWriter(),
	}
}

func (m *authMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.errW.IsSupported(r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		newCtx, err := extractAndParse(ctx, &Request{
			Procedure:  procedureFromHTTP(r),
			ClientAddr: r.RemoteAddr,
			Protocol:   protocolFromHTTP(r),
			Header:     r.Header,
		}, m.handler)
		if err != nil {
			m.errW.Write(w, r, err)
			return
		}
		r = r.WithContext(newCtx)
		next.ServeHTTP(w, r)
	})
}

func procedureFromHTTP(r *http.Request) string {
	path := strings.TrimSuffix(r.URL.Path, "/")
	ultimate := strings.LastIndex(path, "/")
	if ultimate < 0 {
		return ""
	}
	penultimate := strings.LastIndex(path[:ultimate], "/")
	if penultimate < 0 {
		return ""
	}
	procedure := path[penultimate:]
	if len(procedure) < 4 { // two slashes + service + method
		return ""
	}
	return procedure
}

func protocolFromHTTP(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/grpc-web"):
		return connect.ProtocolGRPCWeb
	case strings.HasPrefix(ct, "application/grpc"):
		return connect.ProtocolGRPC
	default:
		return connect.ProtocolConnect
	}
}
