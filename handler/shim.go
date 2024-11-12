package handler

import (
	"context"

	middleware "github.com/washanhanzi/connectrpc-middleware"
)

type Shim interface {
	Skip(ctx context.Context, req *middleware.Request) bool
	Before(ctx context.Context, req *middleware.Request) error
	Success(ctx context.Context, req *middleware.Request) error
	HandleError(ctx context.Context, req *middleware.Request, err error) error
}

type shim struct {
	Skipper      func(ctx context.Context, req *middleware.Request) bool
	BeforeFunc   func(ctx context.Context, req *middleware.Request) error
	SuccessFunc  func(ctx context.Context, req *middleware.Request) error
	ErrorHandler func(ctx context.Context, req *middleware.Request, err error) error
}

type ShimOpt func(*shim)

func NewShim(opts ...ShimOpt) *shim {
	s := shim{}
	for _, o := range opts {
		o(&s)
	}
	if s.Skipper == nil {
		s.Skipper = DefaultSkipper
	}
	if s.BeforeFunc == nil {
		s.BeforeFunc = DefaultBeforeFunc
	}
	if s.SuccessFunc == nil {
		s.SuccessFunc = DefaultSuccessFunc
	}
	if s.ErrorHandler == nil {
		s.ErrorHandler = DefaultErrorHandler
	}
	return &s
}

func DefaultSkipper(ctx context.Context, req *middleware.Request) bool {
	return false
}

func DefaultBeforeFunc(ctx context.Context, req *middleware.Request) error {
	return nil
}

func DefaultSuccessFunc(ctx context.Context, req *middleware.Request) error {
	return nil
}

func DefaultErrorHandler(ctx context.Context, req *middleware.Request, err error) error {
	return err
}

func WithSkipper(skipper func(ctx context.Context, req *middleware.Request) bool) ShimOpt {
	return func(s *shim) {
		s.Skipper = skipper
	}
}

func WithBeforeFunc(beforeFunc func(ctx context.Context, req *middleware.Request) error) ShimOpt {
	return func(s *shim) {
		s.BeforeFunc = beforeFunc
	}
}

func WithSuccessFunc(successFunc func(ctx context.Context, req *middleware.Request) error) ShimOpt {
	return func(s *shim) {
		s.SuccessFunc = successFunc
	}
}

func WithErrorHandler(errorHandler func(ctx context.Context, req *middleware.Request, err error) error) ShimOpt {
	return func(s *shim) {
		s.ErrorHandler = errorHandler
	}
}

func (s *shim) Skip(ctx context.Context, req *middleware.Request) bool {
	return s.Skipper(ctx, req)
}

func (s *shim) Before(ctx context.Context, req *middleware.Request) error {
	return s.BeforeFunc(ctx, req)
}

func (s *shim) Success(ctx context.Context, req *middleware.Request) error {
	return s.SuccessFunc(ctx, req)
}

func (s *shim) HandleError(ctx context.Context, req *middleware.Request, err error) error {
	return s.ErrorHandler(ctx, req, err)
}
