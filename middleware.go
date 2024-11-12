package middleware

import (
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/cockroachdb/errors"
)

type Middleware interface {
	Wrap(http.Handler) http.Handler
}

type authMiddleware struct {
	handler AuthHandler
	errW    *connect.ErrorWriter
}

func NewAuthMiddleware(opts ...authMiddlewareOpt) (*authMiddleware, error) {
	m := authMiddleware{}
	for _, o := range opts {
		o(&m)
	}
	if m.handler == nil {
		return nil, errors.New("handler required")
	}
	if m.errW == nil {
		m.errW = connect.NewErrorWriter()
	}
	return &m, nil
}

type authMiddlewareOpt func(*authMiddleware)

func WithErrorWriterOpts(opts ...connect.HandlerOption) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.errW = connect.NewErrorWriter(opts...)
	}
}

func WithHandler(h AuthHandler) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.handler = h
	}
}

func (m *authMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.errW.IsSupported(r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		req := &Request{
			Procedure:  procedureFromHTTP(r),
			ClientAddr: r.RemoteAddr,
			Protocol:   protocolFromHTTP(r),
			Header:     r.Header,
		}
		if m.handler.Skip(ctx, req) {
			next.ServeHTTP(w, r)
			return
		}
		newCtx, err := extractAndParse(ctx, req, m.handler)
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
