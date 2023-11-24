package middleware

import (
	"context"

	"connectrpc.com/connect"
	"github.com/cockroachdb/errors"
	"github.com/golang-jwt/jwt/v5"
)

type key int

// contextKey is a private key type used as a unique identifier for context value.
// value stored under this key is the result of Parser
// It is defined as its own type to avoid collisions with other user defined context key.
var contextKey key

// FromContext is used to get the payload from context, T is the returned type from parser
func FromContext[T any](ctx context.Context) (T, bool) {
	payload, ok := ctx.Value(contextKey).(T)
	return payload, ok
}

// errParseToken is an error type to identify error from Parser
var errParseToken = errors.New("failed parse token")

// errExtractToken can be used to identify error from Extractor
var errExtractToken = errors.New("failed extract token")

// IsParseTokenErr checks if err is from Parser
// It can be used in ErrorHandle to determine where to err come from
func IsParseTokenErr(err error) bool {
	return errors.Is(err, errParseToken)
}

// IsExtractTokenErr checks if err is from Extractor
func IsExtractTokenErr(err error) bool {
	return errors.Is(err, errExtractToken)
}

type (
	/* Extractor is used to extract token from request,
	R is either `connect.AnyRequest` or `connect.StreamingHandlerConn`
	Extractor's signature take advantage of connect unary and streaming handler has similar function parameters
	which are `func[R connect.AnyRequest](ctx context.Context, req R) <return values>` and
	`func[R connect.StreamingHandlerConn](ctx context.Context, conn R) <return values>`
	*/
	Extractor[R any] func(context.Context, R) ([]string, error)
	//Parser is used to parse token from Extractor
	Parser func(ctx context.Context, token string) (any, error)
	//ClientTokenGetter is used to get token for client request
	ClientTokenGetter interface {
		Get() (string, string)
	}
	//Skipper can return true to skip middleware
	Skipper[R any] func(context.Context, R) bool
	//BeforeOrSuccessFunc is a type served to AuthHandler
	BeforeOrSuccessFunc[R any] func(context.Context, R)
	//ErrorHandle take error from Extractor or Parser, return nil to ignore error
	ErrorHandle[R any] func(context.Context, R, error) error
	//AuthHandler is used in unary and streaming service handler
	AuthHandler[R any] struct {
		Skipper Skipper[R]
		// BeforeFunc defines a function which is executed before Extracor and Parser.
		BeforeFunc BeforeOrSuccessFunc[R]
		// Extractor defines a function which is used to extract token from request.
		Extractor Extractor[R]
		// SuccessFunc defines a function which is executed after Extracor and Parser when they return no error.
		// This function is called after the result of Parser has been set into context
		SuccessFunc BeforeOrSuccessFunc[R]
		// ErrorHandler defines a function which is executed when Extractor or Parser return error.
		ErrorHandler ErrorHandle[R]
	}
	/*authInterceptor serves to wrap unary and streaming interceptor
	It can be used to
	1. set client token
	2. extract and parse token in unary and streaming handler
	authInterceptor could have a generic T which is the return type of Parser
	Adding this generic will add a lot of boilerplate code to NewAuthInterceptor, a viable approach is to use builder pattern to construct authInterceptor
	However, the added generic has no benefit when extract the value from context, user still need to cast the value to the type returned by Parser
	*/
	authInterceptor struct {
		// Context key to store user information from the token into context.
		// Optional. Default value "user".
		parser        Parser
		clientHandler ClientTokenGetter
		unaryHandler  *AuthHandler[connect.AnyRequest]
		streamHandler *AuthHandler[connect.StreamingHandlerConn]
	}
)

// DefaultSkipper returns false which processes the middleware.
func DefaultSkipper[R any](context.Context, R) bool {
	return false
}

type opt func(*authInterceptor)

func NewAuthInterceptor(opts ...opt) (*authInterceptor, error) {
	i := authInterceptor{
		unaryHandler: &AuthHandler[connect.AnyRequest]{
			Skipper: DefaultSkipper[connect.AnyRequest],
		},
	}
	for _, o := range opts {
		o(&i)
	}
	//require at least one handler
	if i.unaryHandler == nil && i.streamHandler == nil && i.clientHandler == nil {
		return nil, errors.New("no handler set")
	}
	//require unary extractor if unary handler is set
	if i.unaryHandler != nil && i.unaryHandler.Extractor == nil {
		return nil, errors.New("no unary extractor set")
	}
	//require stream extractor if stream handler is set
	if i.streamHandler != nil && i.streamHandler.Extractor == nil {
		return nil, errors.New("no stream extractor set")
	}
	//require parser when no client token handler
	if i.clientHandler == nil && i.parser == nil {
		return nil, errors.New("no parser set")
	}
	return &i, nil
}

func (i *authInterceptor) preventNilUnaryHandler() {
	if i.unaryHandler == nil {
		i.unaryHandler = &AuthHandler[connect.AnyRequest]{
			Skipper: DefaultSkipper[connect.AnyRequest],
		}
	}
}

func (i *authInterceptor) preventNilStreamHandler() {
	if i.streamHandler == nil {
		i.streamHandler = &AuthHandler[connect.StreamingHandlerConn]{
			Skipper: DefaultSkipper[connect.StreamingHandlerConn],
		}
	}
}

func WithDefaultBearerExtractorAndParser(signningKey any) opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.parser = DefaultJWTMapClaimsParser(signningKey)
		i.unaryHandler.Extractor = DefaultBearerTokenExtractor().ToUnaryExtractor()
	}
}
func WithDefaultBearerExtractorAndParserUseStream(signningKey any) opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.parser = DefaultJWTMapClaimsParser(signningKey)
		i.unaryHandler.Extractor = DefaultBearerTokenExtractor().ToUnaryExtractor()
		i.preventNilStreamHandler()
		i.streamHandler.Extractor = DefaultBearerTokenExtractor().ToStreamExtractor()
	}
}

func WithDefaultBearerExtractor(useStream bool) opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.unaryHandler.Extractor = DefaultBearerTokenExtractor().ToUnaryExtractor()
		if useStream {
			i.preventNilStreamHandler()
			i.streamHandler.Extractor = DefaultBearerTokenExtractor().ToStreamExtractor()
		}
	}
}

func WithDefaultJWTMapClaimsParser(signningKey any) opt {
	return func(i *authInterceptor) {
		i.parser = DefaultJWTMapClaimsParser(signningKey)
	}
}

// WithCustomJWTClaimsParser sets Parser with signning key and a claimsFunc, the claimsFunc must return a reference
// for example:
//
//	func(ctx context.Context) jwt.Claims{
//		return &jwt.MapClaims{}
//	}
func WithCustomJWTClaimsParser(signningKey any, claimsFunc func(context.Context) jwt.Claims) opt {
	return func(i *authInterceptor) {
		p, _ := NewJWTParser(WithSigningKey(signningKey), WithNewClaimsFunc(claimsFunc))
		i.parser = p.ToParser()
	}
}

func WithIgnoreUnaryError() opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.unaryHandler.ErrorHandler = func(context.Context, connect.AnyRequest, error) error {
			return nil
		}
	}
}

// WithIgnoreStreamError ignores error from Extractor and Parser in streaming handler
func WithIgnoreStreamError() opt {
	return func(i *authInterceptor) {
		i.preventNilStreamHandler()
		i.streamHandler.ErrorHandler = func(context.Context, connect.StreamingHandlerConn, error) error {
			return nil
		}
	}
}

// WithClientTokenGetter sets client token getter when the interceptor in client side
func WithClientTokenGetter(getter ClientTokenGetter) opt {
	return func(i *authInterceptor) {
		i.clientHandler = getter
	}
}

// WithUnarySkipper skip the interceptor for unary handler
func WithUnarySkipper(s Skipper[connect.AnyRequest]) opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.unaryHandler.Skipper = s
	}
}

func WithUnaryBeforeFunc(fn BeforeOrSuccessFunc[connect.AnyRequest]) opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.unaryHandler.BeforeFunc = fn
	}
}

func WithUnarySuccessFunc(fn BeforeOrSuccessFunc[connect.AnyRequest]) opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.unaryHandler.SuccessFunc = fn
	}
}

func WithUnaryErrorHandler(fn ErrorHandle[connect.AnyRequest]) opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.unaryHandler.ErrorHandler = fn
	}
}

func WithUnaryExtractor(fn Extractor[connect.AnyRequest]) opt {
	return func(i *authInterceptor) {
		i.preventNilUnaryHandler()
		i.unaryHandler.Extractor = fn
	}
}

func WithStreamSkipper(s Skipper[connect.StreamingHandlerConn]) opt {
	return func(i *authInterceptor) {
		i.preventNilStreamHandler()
		i.streamHandler.Skipper = s
	}
}

func WithStreamBeforeFunc(fn BeforeOrSuccessFunc[connect.StreamingHandlerConn]) opt {
	return func(i *authInterceptor) {
		i.preventNilStreamHandler()
		i.streamHandler.BeforeFunc = fn
	}
}

func WithStreamSuccessFunc(fn BeforeOrSuccessFunc[connect.StreamingHandlerConn]) opt {
	return func(i *authInterceptor) {
		i.preventNilStreamHandler()
		i.streamHandler.SuccessFunc = fn
	}
}

func WithStreamErrorHandler(fn ErrorHandle[connect.StreamingHandlerConn]) opt {
	return func(i *authInterceptor) {
		i.preventNilStreamHandler()
		i.streamHandler.ErrorHandler = fn
	}
}

func WithStreamExtractor(fn Extractor[connect.StreamingHandlerConn]) opt {
	return func(i *authInterceptor) {
		i.preventNilStreamHandler()
		i.streamHandler.Extractor = fn
	}
}

func WithParser(p Parser) opt {
	return func(i *authInterceptor) {
		i.parser = p
	}
}

func WithNoUnaryHandler() opt {
	return func(i *authInterceptor) {
		i.unaryHandler = nil
	}
}

func WithSkipUnary() opt {
	return func(i *authInterceptor) {
		i.unaryHandler.Skipper = func(context.Context, connect.AnyRequest) bool {
			return true
		}
	}
}
func WithSkipStream() opt {
	return func(i *authInterceptor) {
		i.streamHandler.Skipper = func(context.Context, connect.StreamingHandlerConn) bool {
			return true
		}
	}
}

func (i *authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// check if is a client request, and set the token
		if req.Spec().IsClient {
			if i.clientHandler != nil {
				k, v := i.clientHandler.Get()
				req.Header().Set(k, v)
				return next(ctx, req)
			}
		}
		//check if unary handler is set
		if i.unaryHandler == nil {
			return next(ctx, req)
		}
		ctx, req, err := extractAndParse(ctx, req, i.parser, i.unaryHandler)
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
		if i.streamHandler == nil {
			return next(ctx, conn)
		}

		ctx, conn, err := extractAndParse(ctx, conn, i.parser, i.streamHandler)
		if err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

func extractAndParse[R any](ctx context.Context, req R, p Parser, h *AuthHandler[R]) (context.Context, R, error) {
	if h.Skipper(ctx, req) {
		return ctx, req, nil
	}
	if h.BeforeFunc != nil {
		h.BeforeFunc(ctx, req)
	}

	var extractErr error
	var lastParseErr error
	tokens, err := h.Extractor(ctx, req)
	if err != nil {
		extractErr = errors.Mark(err, errExtractToken)
	}
	for _, t := range tokens {
		payload, err := p(ctx, t)
		if err != nil {
			lastParseErr = errors.Mark(err, errParseToken)
			continue
		}
		ctx = context.WithValue(ctx, contextKey, payload)
		if h.SuccessFunc != nil {
			h.SuccessFunc(ctx, req)
		}
		return ctx, req, nil
	}

	// prioritize token parsing errors over extracting errors as parsing is occurs further in process, meaning we managed to
	// extract at least one token and failed to parse it
	joinErr := errors.Join(lastParseErr, extractErr)
	if h.ErrorHandler != nil {
		tmpErr := h.ErrorHandler(ctx, req, joinErr)
		if tmpErr == nil {
			return ctx, req, nil
		}
		return ctx, req, tmpErr
	}
	if lastParseErr != nil {
		return ctx, req, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
	}
	return ctx, req, connect.NewError(connect.CodeUnauthenticated, errors.New("missing or malformed token"))
}
