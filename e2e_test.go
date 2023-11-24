package middleware

import (
	"context"
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
			validator(ctx)
			return next(ctx, req)
		}
	})
	is := connect.WithInterceptors(interceptor, logger)
	mux := http.NewServeMux()
	mux.Handle(pingv1connect.NewPingServiceHandler(&pingServer{}, is))
	return memhttptest.New(t, mux)
}
func TestE2E(t *testing.T) {
	authInterceptor, err := NewAuthInterceptor(WithDefaultBearerExtractorAndParser([]byte("secret")))
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
	assert.Equal(t, err.(*connect.Error).Code(), connect.CodeUnimplemented)
}
