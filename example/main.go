package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	middleware "github.com/washanhanzi/connectrpc-middleware"
	pingv1 "github.com/washanhanzi/connectrpc-middleware/example/gen/ping/v1"
	"github.com/washanhanzi/connectrpc-middleware/example/gen/ping/v1/pingv1connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	// generated by protoc-gen-connect-go
)

type PingServer struct {
	pingv1connect.UnimplementedPingServiceHandler
}

func (s *PingServer) Ping(
	ctx context.Context,
	req *connect.Request[pingv1.PingRequest],
) (*connect.Response[pingv1.PingResponse], error) {
	payload, ok := middleware.FromContext[jwt.MapClaims](ctx)
	log.Println(payload, ok)
	res := connect.NewResponse(&pingv1.PingResponse{
		Text: "hello world",
	})
	return res, nil
}

func (s *PingServer) CumSum(
	ctx context.Context,
	stream *connect.BidiStream[pingv1.CumSumRequest, pingv1.CumSumResponse],
) error {
	var count int64 = 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		payload, ok := middleware.FromContext[jwt.MapClaims](ctx)
		log.Println(payload, ok)
		log.Println("Request headers: ", stream.RequestHeader())

		request, err := stream.Receive()
		if err != nil && errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("receive request: %w", err)
		}

		count = count + request.Number
		if err := stream.Send(&pingv1.CumSumResponse{Sum: count}); err != nil {
			return fmt.Errorf("send response: %w", err)
		}
	}
}

func main() {
	// auth, err := middleware.NewAuthInterceptor(middleware.WithInterceptorDefaultBearerExtractorAndParser([]byte("secret")))
	// if err != nil {
	// 	panic(err)
	// }
	// interceptors := connect.WithInterceptors(auth)
	greeter := &PingServer{pingv1connect.UnimplementedPingServiceHandler{}}
	mux := http.NewServeMux()
	mux.Handle(pingv1connect.NewPingServiceHandler(greeter))
	authMiddleware, err := middleware.NewAuthMiddleware(middleware.WithDefaultBearerExtractorAndParser([]byte("secret")))
	if err != nil {
		panic(err)
	}
	http.ListenAndServe(
		"localhost:8080",
		// Use h2c so we can serve HTTP/2 without TLS.
		h2c.NewHandler(authMiddleware.Wrap(mux), &http2.Server{}),
	)
}
