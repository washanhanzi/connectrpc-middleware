package middleware

import (
	"context"
	"net/http"

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
	// ClientTokenGetter is used to get token for client request
	ClientTokenGetter interface {
		Get() (string, string)
	}
	// AuthHandler is used in unary and streaming service handler
	// The order of execution of handler's functions are:
	// Skip(if this function return true, skip the rest process) ->
	// Before(if this function return err, skip the rest process) ->
	// Extract(if this function return err, jump to HandleError) ->
	// Parse (if this function return err, jump to HandleError) ->
	// Success(if this function return err, the error is returned) ->
	// HandleError
	AuthHandler interface {
		//Skip defines a function to skip the middleware
		Skip(ctx context.Context, req *Request) bool
		// Before defines a function which is executed before Extracor and Parser
		// If this function return an error, the middleware will return the error and skip the rest of the process
		// HandleError will be ignored if Before return an error
		Before(ctx context.Context, req *Request) error
		// Extract defines a function which is used to extract data from request, and write to repository
		Extract(ctx context.Context, req *Request) (context.Context, error)
		// Parse is used to parse data from a repository
		Parse(ctx context.Context) (any, error)
		// Success defines a function which is executed after Extracor and Parser when they return no error.
		// This function accepts the context, the request and the payload returned by Parser.
		// If this function return an error, the middleware will return with the error and skip error handler.
		// HandleError will be ignored if Success return an error.
		Success(ctx context.Context, req *Request) error
		// HandleError defines a function which is executed when Extractor or Parser return error.
		HandleError(ctx context.Context, req *Request, err error) error
	}
)

// DefaultSkipper returns false which processes the middleware.
func DefaultSkipper(context.Context, *Request) bool {
	return false
}

func extractAndParse(ctx context.Context, req *Request, h AuthHandler) (context.Context, error) {
	err := h.Before(ctx, req)
	if err != nil {
		return ctx, err
	}

	ctx, extractErr := h.Extract(ctx, req)
	if extractErr != nil {
		extractErr = errors.Mark(extractErr, errExtractToken)
		err := h.HandleError(ctx, req, extractErr)
		if err == nil {
			return ctx, nil
		}
		return ctx, err
	}
	payload, parseErr := h.Parse(ctx)
	if parseErr != nil {
		parseErr = errors.Mark(parseErr, errParseToken)
		err := h.HandleError(ctx, req, parseErr)
		if err == nil {
			return ctx, nil
		}
		return ctx, err
	}
	ctx = NewContext(ctx, payload)
	successErr := h.Success(ctx, req)
	if successErr != nil {
		return ctx, successErr
	}
	return ctx, nil
}
