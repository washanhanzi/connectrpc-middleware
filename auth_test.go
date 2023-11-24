package middleware

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/cockroachdb/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/test-go/testify/assert"
	pingv1 "github.com/washanhanzi/connectrpc-middleware/example/gen/ping/v1"
)

// jwtCustomClaims are custom claims expanding default ones.
type jwtCustomClaims struct {
	*jwt.RegisteredClaims
	jwtCustomInfo
}

var unaryAuthTests = []struct {
	Case        string
	Interceptor func(t *testing.T) connect.Interceptor
	Request     func() *connect.Request[pingv1.PingRequest]
	Handler     func(t *testing.T) connect.UnaryFunc
	Code        connect.Code
}{
	{
		Case: "skip",
		Interceptor: func(t *testing.T) connect.Interceptor {
			interceptor, err := NewAuthInterceptor(WithDefaultBeearerExtractorAndParser([]byte("secret")), WithSkipUnary())
			assert.Nil(t, err)
			return interceptor
		},
		Request: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set(HeaderAuthorization, validAuth)
			return req
		},
		Handler: func(t *testing.T) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				claims, ok := FromContext[jwt.MapClaims](ctx)
				assert.False(t, ok)
				assert.Nil(t, claims)
				return nil, nil
			}
		},
	},
	{
		Case: "ignore error",
		Interceptor: func(t *testing.T) connect.Interceptor {
			interceptor, err := NewAuthInterceptor(WithDefaultBeearerExtractorAndParser([]byte("secret")), WithIgnoreUnaryError())
			assert.Nil(t, err)
			return interceptor
		},
		Request: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set(HeaderAuthorization, invalidAuth)
			return req
		},
		Handler: func(t *testing.T) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				claims, ok := FromContext[jwt.MapClaims](ctx)
				assert.False(t, ok)
				assert.Nil(t, claims)
				return nil, nil
			}
		},
	},
	{
		Case: "invalid bearer token",
		Interceptor: func(t *testing.T) connect.Interceptor {
			interceptor, err := NewAuthInterceptor(WithDefaultBeearerExtractorAndParser([]byte("secret")))
			assert.Nil(t, err)
			return interceptor
		},
		Request: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set(HeaderAuthorization, invalidAuth)
			return req
		},
		Handler: func(t *testing.T) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				claims, ok := FromContext[jwt.MapClaims](ctx)
				assert.False(t, ok)
				assert.Nil(t, claims)
				return nil, nil
			}
		},
		Code: connect.CodeUnauthenticated,
	},
	{
		Case: "invalid auth header",
		Interceptor: func(t *testing.T) connect.Interceptor {
			interceptor, err := NewAuthInterceptor(WithDefaultBeearerExtractorAndParser([]byte("secret")))
			assert.Nil(t, err)
			return interceptor
		},
		Request: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set("auth", invalidAuth)
			return req
		},
		Handler: func(t *testing.T) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				claims, ok := FromContext[jwt.MapClaims](ctx)
				assert.False(t, ok)
				assert.Nil(t, claims)
				return nil, nil
			}
		},
		Code: connect.CodeUnauthenticated,
	},
	{
		Case: "invalid signing key",
		Interceptor: func(t *testing.T) connect.Interceptor {
			interceptor, err := NewAuthInterceptor(WithDefaultBeearerExtractorAndParser([]byte("secet")))
			assert.Nil(t, err)
			return interceptor
		},
		Request: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set(HeaderAuthorization, validAuth)
			return req
		},
		Handler: func(t *testing.T) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				claims, ok := FromContext[jwt.MapClaims](ctx)
				assert.False(t, ok)
				assert.Nil(t, claims)
				return nil, nil
			}
		},
		Code: connect.CodeUnauthenticated,
	},
	{
		Case: "default",
		Interceptor: func(t *testing.T) connect.Interceptor {
			interceptor, err := NewAuthInterceptor(WithDefaultBeearerExtractorAndParser([]byte("secret")))
			assert.Nil(t, err)
			return interceptor
		},
		Request: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set(HeaderAuthorization, validAuth)
			return req
		},
		Handler: func(t *testing.T) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				claims, ok := FromContext[jwt.MapClaims](ctx)
				assert.True(t, ok)
				assert.Equal(t, claims["name"], "John Doe")
				assert.Equal(t, claims["admin"], true)
				assert.Equal(t, claims["sub"], "1234567890")
				return nil, nil
			}
		},
	},
	{
		Case: "custom claim",
		Interceptor: func(t *testing.T) connect.Interceptor {
			interceptor, err := NewAuthInterceptor(
				WithDefaultBearerTokenExtractor(false),
				WithCustomJWTClaimsParser([]byte("secret"), func(ctx context.Context) jwt.Claims {
					return &jwtCustomClaims{}
				}),
			)
			assert.Nil(t, err)
			return interceptor
		},
		Request: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set(HeaderAuthorization, validAuth)
			return req
		},
		Handler: func(t *testing.T) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				claims, ok := FromContext[customClaims](ctx)
				assert.True(t, ok)
				assert.Equal(t, claims.jwtCustomInfo.Name, "John Doe")
				assert.Equal(t, claims.jwtCustomInfo.Admin, true)
				return nil, nil
			}
		},
	},
}

func TestUnaryAuth(t *testing.T) {
	t.Parallel()
	for _, tt := range unaryAuthTests {
		t.Run(tt.Case, func(t *testing.T) {
			ctx := context.Background()
			_, err := tt.Interceptor(t).WrapUnary(tt.Handler(t))(ctx, tt.Request())
			if err != nil {
				assert.Equal(t, err.(*connect.Error).Code(), tt.Code)
			}
		})
	}
}

func TestErr(t *testing.T) {
	t.Parallel()
	t.Run("is parse err", func(t *testing.T) {
		e := errors.New("parse err")
		e = errors.Mark(e, errParseToken)
		is := IsParseTokenErr(e)
		not := IsExtractTokenErr(e)
		assert.True(t, is)
		assert.False(t, not)
	})
	t.Run("is extract err", func(t *testing.T) {
		e := errors.New("extract err")
		e = errors.Mark(e, errExtractToken)
		is := IsExtractTokenErr(e)
		not := IsParseTokenErr(e)
		assert.True(t, is)
		assert.False(t, not)
	})
	t.Run("is parse and extract err", func(t *testing.T) {
		pe := errors.New("parse err")
		pe = errors.Mark(pe, errParseToken)
		ee := errors.New("extract err")
		ee = errors.Mark(ee, errExtractToken)
		isPe := IsParseTokenErr(pe)
		notEe := IsExtractTokenErr(pe)
		isEe := IsExtractTokenErr(ee)
		notPe := IsParseTokenErr(ee)
		assert.True(t, isPe)
		assert.True(t, isEe)
		assert.False(t, notEe)
		assert.False(t, notPe)
	})

}
