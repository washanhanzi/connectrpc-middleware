package middleware

import (
	"context"

	"connectrpc.com/connect"
	"github.com/cockroachdb/errors"
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
	serviceHandler AuthHandler
}

type authInterceptorOpt func(*authInterceptor)

func NewAuthInterceptor(opts ...authInterceptorOpt) (*authInterceptor, error) {
	i := authInterceptor{}
	for _, o := range opts {
		o(&i)
	}
	//require at least one handler
	if i.serviceHandler == nil && i.clientHandler == nil {
		return nil, errors.New("no handler set")
	}
	return &i, nil
}

func WithClientHandler(h ClientTokenGetter) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.clientHandler = h
	}
}

func WithUnaryServiceHandler(h AuthHandler) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.ServiceHandlerType = UnaryHandler
		i.serviceHandler = h
	}
}

func WithStreamServiceHandler(h AuthHandler) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.ServiceHandlerType = StreamHandler
		i.serviceHandler = h
	}
}

func WithServiceHandler(h AuthHandler) authInterceptorOpt {
	return func(i *authInterceptor) {
		i.ServiceHandlerType = UnaryAndStreamHandler
		i.serviceHandler = h
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
		if i.serviceHandler.Skip(ctx, parseReq) {
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
		if i.serviceHandler.Skip(ctx, req) {
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
