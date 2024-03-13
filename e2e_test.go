package middleware

import (
	"context"
	"errors"
	"log"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/test-go/testify/assert"
	pingv1 "github.com/washanhanzi/connectrpc-middleware/example/gen/ping/v1"
	"github.com/washanhanzi/connectrpc-middleware/example/gen/ping/v1/pingv1connect"
	"go.akshayshah.org/memhttp"
	"go.akshayshah.org/memhttp/memhttptest"
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
	authInterceptor, err := NewAuthInterceptor(WithInterceptorDefaultBearerExtractorAndParser(validKey))
	assert.Nil(t, err)
	s := newServer(t, authInterceptor, func(ctx context.Context) {
		claims, ok := FromContext[jwt.MapClaims](ctx)
		assert.True(t, ok)
		assert.Equal(t, claims["name"], "John Doe")
		assert.Equal(t, claims["admin"], true)
	})
	req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
	req.Header().Set(HeaderAuthorization, validAuth)
	client := pingv1connect.NewPingServiceClient(s.Client(), s.URL())
	_, err = client.Ping(context.Background(), req)
	assert.Equal(t, connect.CodeUnimplemented, err.(*connect.Error).Code())
}

func TestBeforeFunc(t *testing.T) {
	authInterceptor, err := NewAuthInterceptor(WithInterceptorDefaultBearerExtractorAndParser(validKey), WithInterceptorBeforeFunc(func(ctx context.Context, r *Request) error {
		return connect.NewError(connect.CodeAborted, errors.New("aborted"))
	}))
	assert.Nil(t, err)
	s := newServer(t, authInterceptor, func(ctx context.Context) {
		claims, ok := FromContext[jwt.MapClaims](ctx)
		assert.True(t, ok)
		assert.Equal(t, claims["name"], "John Doe")
		assert.Equal(t, claims["admin"], true)
	})
	req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
	req.Header().Set(HeaderAuthorization, validAuth)
	client := pingv1connect.NewPingServiceClient(s.Client(), s.URL())
	_, err = client.Ping(context.Background(), req)
	assert.Equal(t, connect.CodeAborted, err.(*connect.Error).Code())
}

func TestSuccessFunc(t *testing.T) {
	authInterceptor, err := NewAuthInterceptor(WithInterceptorDefaultBearerExtractorAndParser(validKey), WithInterceptorSuccessFunc(func(ctx context.Context, r *Request, payload any) error {
		assert.Equal(t, "John Doe", payload.(jwt.MapClaims)["name"])
		assert.Equal(t, true, payload.(jwt.MapClaims)["admin"])
		return connect.NewError(connect.CodeAborted, errors.New("aborted"))
	}))
	assert.Nil(t, err)
	s := newServer(t, authInterceptor, func(ctx context.Context) {
		claims, ok := FromContext[jwt.MapClaims](ctx)
		assert.True(t, ok)
		assert.Equal(t, "John Doe", claims["name"])
		assert.Equal(t, true, claims["admin"])
	})
	req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
	req.Header().Set(HeaderAuthorization, validAuth)
	client := pingv1connect.NewPingServiceClient(s.Client(), s.URL())
	_, err = client.Ping(context.Background(), req)
	assert.Equal(t, connect.CodeAborted, err.(*connect.Error).Code())
}
