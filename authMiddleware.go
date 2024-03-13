package middleware

import (
	"context"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/cockroachdb/errors"
	"github.com/golang-jwt/jwt/v5"
)

type authMiddleware struct {
	handler *AuthHandler
	errW    *connect.ErrorWriter
}

func NewAuthMiddleware(opts ...authMiddlewareOpt) (*authMiddleware, error) {
	m := authMiddleware{}
	for _, o := range opts {
		o(&m)
	}
	if m.handler == nil {
		return nil, errors.New("no handler set")
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

func (m *authMiddleware) preventNilHandler() {
	if m.handler == nil {
		m.handler = &AuthHandler{
			Skipper: DefaultSkipper,
		}
	}
}

func WithDefaultBearerExtractor() authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.preventNilHandler()
		m.handler.Extractor = DefaultBasicAuthExtractor().ToExtractor()
	}
}

func WithDefaultBearerExtractorAndParser(signningKey any) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.preventNilHandler()
		m.handler.Extractor = DefaultBearerTokenExtractor().ToExtractor()
		m.handler.Parser = DefaultJWTMapClaimsParser(signningKey)
	}
}

func WithDefaultJWTMapClaimsParser(signningKey any) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.handler.Parser = DefaultJWTMapClaimsParser(signningKey)
	}
}

// WithCustomJWTClaimsParser sets Parser with signning key and a claimsFunc, the claimsFunc must return a reference
// for example:
//
//	func(ctx context.Context) jwt.Claims{
//		return &jwt.MapClaims{}
//	}
func WithCustomJWTClaimsParser(signningKey any, claimsFunc func(context.Context) jwt.Claims) authMiddlewareOpt {
	return func(m *authMiddleware) {
		p, _ := NewJWTParser(WithSigningKey(signningKey), WithNewClaimsFunc(claimsFunc))
		m.handler.Parser = p.ToParser()
	}
}

func WithIgnoreError() authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.preventNilHandler()
		m.handler.ErrorHandler = func(context.Context, *Request, error) error {
			return nil
		}
	}
}

// WithUnarySkipper skip the interceptor for unary handler
func WithSkipper(s Skipper) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.preventNilHandler()
		m.handler.Skipper = s
	}
}

func WithBeforeFunc(fn BeforeFunc) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.preventNilHandler()
		m.handler.BeforeFunc = fn
	}
}

func WithSuccessFunc(fn SuccessFunc) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.handler.SuccessFunc = fn
	}
}

func WithErrorHandler(fn ErrorHandle) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.preventNilHandler()
		m.handler.ErrorHandler = fn
	}
}

func WithExtractor(fn Extractor) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.preventNilHandler()
		m.handler.Extractor = fn
	}
}

func WithParser(p Parser) authMiddlewareOpt {
	return func(m *authMiddleware) {
		m.handler.Parser = p
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
		if m.handler.Skipper(ctx, req) {
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
