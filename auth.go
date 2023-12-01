package middleware

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/cockroachdb/errors"
)

type key int

// contextKey is a private key type used as a unique identifier for context value.
// value stored under this key is the result of Parser
// It is defined as its own type to avoid collisions with other user defined context key.
var contextKey key

func NewContext(ctx context.Context, payload any) context.Context {
	if ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey, payload)
}

// FromContext is used to get the payload from context, T is the returned type from parser
func FromContext[T any](ctx context.Context) (T, bool) {
	payload, ok := ctx.Value(contextKey).(T)
	return payload, ok
}

// Request describes a single RPC invocation.
type Request struct {
	Procedure  string // for example, "/acme.foo.v1.FooService/Bar"
	ClientAddr string // client address, in IP:port format
	Protocol   string // connect.ProtocolConnect, connect.ProtocolGRPC, or connect.ProtocolGRPCWeb
	Header     http.Header
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
	The returned map contain all the information extracted from the request header, it is a map of headerName->[]headerValues
	*/
	Extractor func(context.Context, *Request) (ExtractedHeader, error)
	//Parser is used to parse tokens from Extractor
	Parser func(ctx context.Context, extractedHeader ExtractedHeader) (any, error)
	//ClientTokenGetter is used to get token for client request
	ClientTokenGetter interface {
		Get() (string, string)
	}
	//Skipper can return true to skip middleware
	Skipper func(context.Context, *Request) bool
	//BeforeOrSuccessFunc is a type served to AuthHandler
	BeforeOrSuccessFunc func(context.Context, *Request)
	//ErrorHandle take error from Extractor or Parser, return nil to ignore error
	ErrorHandle func(context.Context, *Request, error) error
	//AuthHandler is used in unary and streaming service handler
	AuthHandler struct {
		Skipper Skipper
		// BeforeFunc defines a function which is executed before Extracor and Parser.
		BeforeFunc BeforeOrSuccessFunc
		// Extractor defines a function which is used to extract token from request.
		Extractor Extractor
		Parser    Parser
		// SuccessFunc defines a function which is executed after Extracor and Parser when they return no error.
		// This function is called after the result of Parser has been set into context
		SuccessFunc BeforeOrSuccessFunc
		// ErrorHandler defines a function which is executed when Extractor or Parser return error.
		ErrorHandler ErrorHandle
	}
)

// DefaultSkipper returns false which processes the middleware.
func DefaultSkipper(context.Context, *Request) bool {
	return false
}

func extractAndParse(ctx context.Context, req *Request, h *AuthHandler) (context.Context, error) {
	if h.BeforeFunc != nil {
		h.BeforeFunc(ctx, req)
	}

	var extractErr error
	var parseErr error
	tokens, err := h.Extractor(ctx, req)
	if err != nil {
		extractErr = errors.Mark(err, errExtractToken)
	}
	if len(tokens) != 0 {
		payload, err := h.Parser(ctx, tokens)
		if err == nil {
			ctx = NewContext(ctx, payload)
			if h.SuccessFunc != nil {
				h.SuccessFunc(ctx, req)
			}
			return ctx, nil
		}
		parseErr = errors.Mark(err, errParseToken)
	}

	// prioritize token parsing errors over extracting errors as parsing is occurs further in process, meaning we managed to
	// extract at least one token and failed to parse it
	joinErr := errors.Join(parseErr, extractErr)
	if h.ErrorHandler != nil {
		tmpErr := h.ErrorHandler(ctx, req, joinErr)
		if tmpErr == nil {
			return ctx, nil
		}
		return ctx, tmpErr
	}
	if parseErr != nil {
		return ctx, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
	}
	return ctx, connect.NewError(connect.CodeUnauthenticated, errors.New("missing or malformed token"))
}
