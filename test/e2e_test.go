package test

import (
	"context"
	"errors"
	"log"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/test-go/testify/assert"
	middleware "github.com/washanhanzi/connectrpc-middleware"
	pingv1 "github.com/washanhanzi/connectrpc-middleware/example/gen/ping/v1"
	"github.com/washanhanzi/connectrpc-middleware/example/gen/ping/v1/pingv1connect"
	"github.com/washanhanzi/connectrpc-middleware/handler"
	"go.akshayshah.org/memhttp"
	"go.akshayshah.org/memhttp/memhttptest"
)

var (
	token       = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	validKey    = []byte("secret")
	invalidKey  = []byte("invalid-key")
	validAuth   = "Bearer " + token
	invalidAuth = "Bearer invalid-token"
)

type pingServer struct {
	pingv1connect.UnimplementedPingServiceHandler
}

func newServer(t *testing.T, interceptor connect.Interceptor, validator func(context.Context)) *memhttp.Server {
	logger := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			log.Println("Request headers: ", req.Header())
			validator(ctx)
			return next(ctx, req)
		}
	})
	interceptors := connect.WithInterceptors(interceptor, logger)
	mux := http.NewServeMux()
	mux.Handle(pingv1connect.NewPingServiceHandler(&pingServer{}, interceptors))
	return memhttptest.New(t, mux)
}

func TestNormalInterceptor(t *testing.T) {
	jwtHandler := handler.NewJWTHandler(handler.NewShim(), handler.WithJwtMapClaimsParser(validKey))
	authInterceptor, err := middleware.NewAuthInterceptor(middleware.WithServiceHandler(jwtHandler))
	assert.Nil(t, err)
	s := newServer(t, authInterceptor, func(ctx context.Context) {
		claims, ok := middleware.FromContext[jwt.MapClaims](ctx)
		assert.True(t, ok)
		assert.Equal(t, claims["name"], "John Doe")
		assert.Equal(t, claims["admin"], true)
	})
	req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
	req.Header().Set("Authorization", validAuth)
	client := pingv1connect.NewPingServiceClient(s.Client(), s.URL())
	_, err = client.Ping(context.Background(), req)
	assert.Equal(t, connect.CodeUnimplemented, err.(*connect.Error).Code())
}

func TestBeforeFunc(t *testing.T) {
	jwtHandler := handler.NewJWTHandler(
		handler.NewShim(
			handler.WithBeforeFunc(func(ctx context.Context, req *middleware.Request) error {
				return connect.NewError(connect.CodeAborted, errors.New("aborted"))
			}),
		),
		handler.WithJwtMapClaimsParser(validKey),
	)
	authInterceptor, err := middleware.NewAuthInterceptor(
		middleware.WithServiceHandler(jwtHandler),
	)
	assert.Nil(t, err)
	s := newServer(t, authInterceptor, func(ctx context.Context) {
		claims, ok := middleware.FromContext[jwt.MapClaims](ctx)
		assert.True(t, ok)
		assert.Equal(t, claims["name"], "John Doe")
		assert.Equal(t, claims["admin"], true)
	})
	req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
	req.Header().Set("Authorization", validAuth)
	client := pingv1connect.NewPingServiceClient(s.Client(), s.URL())
	_, err = client.Ping(context.Background(), req)
	assert.Equal(t, connect.CodeAborted, err.(*connect.Error).Code())
}

func TestSuccessFunc(t *testing.T) {
	jwtHandler := handler.NewJWTHandler(
		handler.NewShim(
			handler.WithSuccessFunc(func(ctx context.Context, req *middleware.Request) error {
				claims, _ := middleware.FromContext[jwt.MapClaims](ctx)
				assert.Equal(t, "John Doe", claims["name"])
				assert.Equal(t, true, claims["admin"])
				return connect.NewError(connect.CodeAborted, errors.New("aborted"))
			}),
		),
		handler.WithJwtMapClaimsParser(validKey),
	)
	authInterceptor, err := middleware.NewAuthInterceptor(
		middleware.WithServiceHandler(jwtHandler),
	)
	assert.Nil(t, err)
	s := newServer(t, authInterceptor, func(ctx context.Context) {
		claims, ok := middleware.FromContext[jwt.MapClaims](ctx)
		assert.True(t, ok)
		assert.Equal(t, "John Doe", claims["name"])
		assert.Equal(t, true, claims["admin"])
	})
	req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
	req.Header().Set("Authorization", validAuth)
	client := pingv1connect.NewPingServiceClient(s.Client(), s.URL())
	_, err = client.Ping(context.Background(), req)
	assert.Equal(t, connect.CodeAborted, err.(*connect.Error).Code())
}
