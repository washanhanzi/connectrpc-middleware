package middleware

import (
	"context"

	"connectrpc.com/connect"
	"github.com/cockroachdb/errors"
	"github.com/golang-jwt/jwt/v5"
)

type ServiceHandlerType int

const (
	UnaryHandler ServiceHandlerType = 1 << iota
	StreamHandler
)
const (
	UnaryAndStreamHandler = UnaryHandler | StreamHandler
)

/*
authInterceptor serves to wrap unary and streaming interceptor
It can be used to
1. set client token
2. extract and parse token in unary and streaming handler
authInterceptor could have a generic T which is the return type of Parser
Adding this generic will add a lot of boilerplate code to NewAuthInterceptor, a viable approach is to use builder pattern to construct authInterceptor
However, the added generic has no benefit when extract the value from context, user still need to cast the value to the type returned by Parser
*/
type authInterceptor struct {
	ServiceHandlerType
	clientHandler  ClientTokenGetter
	serviceHandler *AuthHandler
}

type authInterceptorOpt func(*authInterceptor)

func NewAuthInterceptor(opts ...authInterceptorOpt) (*authInterceptor, error) {
	i := authInterceptor{
		ServiceHandlerType: UnaryHandler,
		serviceHandler: &AuthHandler{
			Skipper: DefaultSkipper,
		},
	}
	for _, o := range opts {
		o(&i)
	}
	//require at least one handler
	if i.serviceHandler == nil && i.clientHandler == nil {
		return nil, errors.New("no handler set")
	}

	if i.serviceHandler != nil {
		if i.serviceHandler.Extractor == nil {
			return nil, errors.New("no extractor set")
		}
		if i.serviceHandler.Parser == nil {
			return nil, errors.New("no parser set")
		}
	}
	return &i, nil
}

func (i *authInterceptor) preventNilServiceHandler() {
	if i.serviceHandler == nil {
		i.serviceHandler = &AuthHandler{
			Skipper: DefaultSkipper,
		}
	}
}

func WithInterceptorDefaultBearerExtractor() authInterceptorOpt {
	return func(i *authInterceptor) {
		i.preventNilServiceHandler()
		i.serviceHandler.Extractor = DefaultBearerTokenExtractor().ToExtractor()
	}
}

func WithInterceptorDefaultBearerExtractorAndParser(signningKey any) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.preventNilServiceHandler()
		i.serviceHandler.Parser = DefaultJWTMapClaimsParser(signningKey)
		i.serviceHandler.Extractor = DefaultBearerTokenExtractor().ToExtractor()
	}
}

func WithInterceptorDefaultJWTMapClaimsParser(signningKey any) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.serviceHandler.Parser = DefaultJWTMapClaimsParser(signningKey)
	}
}

// WithCustomJWTClaimsParser sets Parser with signning key and a claimsFunc, the claimsFunc must return a reference
// for example:
//
//	func(ctx context.Context) jwt.Claims{
//		return &jwt.MapClaims{}
//	}
func WithInterceptorCustomJWTClaimsParser(signningKey any, claimsFunc func(context.Context) jwt.Claims) authInterceptorOpt {
	return func(i *authInterceptor) {
		p, _ := NewJWTParser(WithSigningKey(signningKey), WithNewClaimsFunc(claimsFunc))
		i.serviceHandler.Parser = p.ToParser()
	}
}

func WithInterceptorIgnoreError() authInterceptorOpt {
	return func(i *authInterceptor) {
		i.preventNilServiceHandler()
		i.serviceHandler.ErrorHandler = func(context.Context, *Request, error) error {
			return nil
		}
	}
}

// WithClientTokenGetter sets client token getter when the interceptor in client side
func WithInterceptorClientTokenGetter(getter ClientTokenGetter) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.clientHandler = getter
	}
}

// WithUnarySkipper skip the interceptor for unary handler
func WithInterceptorSkipper(s Skipper) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.preventNilServiceHandler()
		i.serviceHandler.Skipper = s
	}
}

func WithInterceptorBeforeFunc(fn BeforeFunc) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.preventNilServiceHandler()
		i.serviceHandler.BeforeFunc = fn
	}
}

func WithInterceptorSuccessFunc(fn SuccessFunc) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.preventNilServiceHandler()
		i.serviceHandler.SuccessFunc = fn
	}
}

func WithInterceptorErrorHandler(fn ErrorHandle) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.preventNilServiceHandler()
		i.serviceHandler.ErrorHandler = fn
	}
}

func WithInterceptorExtractor(fn Extractor) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.preventNilServiceHandler()
		i.serviceHandler.Extractor = fn
	}
}

func WithInterceptorParser(p Parser) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.serviceHandler.Parser = p
	}
}

func WithServiceHandlerType(s ServiceHandlerType) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.ServiceHandlerType = s
	}
}

func (i *authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		spec := req.Spec()
		// check if is a client request, and set the token
		if spec.IsClient {
			if i.clientHandler != nil {
				k, v := i.clientHandler.Get()
				req.Header().Set(k, v)
				return next(ctx, req)
			}
		}
		//check if unary handler is set
		if i.ServiceHandlerType&UnaryHandler == 0 {
			return next(ctx, req)
		}
		peer := req.Peer()
		parseReq := &Request{
			Procedure:  spec.Procedure,
			ClientAddr: peer.Addr,
			Protocol:   peer.Protocol,
			Header:     req.Header(),
		}
		if i.serviceHandler.Skipper(ctx, parseReq) {
			return next(ctx, req)
		}
		ctx, err := extractAndParse(
			ctx,
			parseReq,
			i.serviceHandler,
		)
		if err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (i *authInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		if i.clientHandler != nil {
			conn := next(ctx, spec)
			k, v := i.clientHandler.Get()
			conn.RequestHeader().Set(k, v)
			return conn
		}
		return next(ctx, spec)
	}
}

func (i *authInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		//check if stream handler is set
		if i.ServiceHandlerType&StreamHandler == 0 {
			return next(ctx, conn)
		}
		peer := conn.Peer()
		req := &Request{
			Procedure:  conn.Spec().Procedure,
			ClientAddr: peer.Addr,
			Protocol:   peer.Protocol,
			Header:     conn.RequestHeader(),
		}
		if i.serviceHandler.Skipper(ctx, req) {
			return next(ctx, conn)
		}
		ctx, err := extractAndParse(
			ctx,
			req,
			i.serviceHandler,
		)
		if err != nil {
			return err
		}
		return next(ctx, conn)
	}
}
