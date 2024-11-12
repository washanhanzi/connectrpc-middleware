package handler

import (
	"context"
	"fmt"

	middleware "github.com/washanhanzi/connectrpc-middleware"
	"github.com/washanhanzi/connectrpc-middleware/extractor"
	"github.com/washanhanzi/connectrpc-middleware/parser"
)

type key int

var handlerKey key

type JWTHandler struct {
	Capacity         int
	HeaderExtractors []extractor.HeaderExtractor
	Parser           parser.JwtParser
	ExtractFunc      func(ctx context.Context, req *middleware.Request) (context.Context, error)
	ParseFunc        func(ctx context.Context) (any, error)
	Shim
}

type jwtHandlerOpt func(*JWTHandler)

func NewJWTHandler(shim Shim, opts ...jwtHandlerOpt) *JWTHandler {
	h := &JWTHandler{Shim: shim}
	for _, o := range opts {
		o(h)
	}
	if len(h.HeaderExtractors) == 0 {
		h.HeaderExtractors = append(h.HeaderExtractors, extractor.JwtTokenExtractor())
	}
	return h
}

func WithExtractor(extractor extractor.HeaderExtractor) jwtHandlerOpt {
	return func(h *JWTHandler) {
		h.HeaderExtractors = append(h.HeaderExtractors, extractor)
	}
}

func WithParser(parser parser.JwtParser) jwtHandlerOpt {
	return func(h *JWTHandler) {
		h.Parser = parser
	}
}

func WithJwtMapClaimsParser(signingKey any) jwtHandlerOpt {
	return func(h *JWTHandler) {
		parser, err := parser.NewJwtParser(parser.WithJWTMapClaims(signingKey))
		if err != nil {
			//log the error
			fmt.Println("error creating jwt parser: ", err)
		}
		h.Parser = parser
	}
}

func WithExtractFunc(f func(ctx context.Context, req *middleware.Request) (context.Context, error)) jwtHandlerOpt {
	return func(h *JWTHandler) {
		h.ExtractFunc = f
	}
}

func WithParseFunc(f func(ctx context.Context) (any, error)) jwtHandlerOpt {
	return func(h *JWTHandler) {
		h.ParseFunc = f
	}
}

func (h *JWTHandler) Extract(ctx context.Context, req *middleware.Request) (context.Context, error) {
	if h.ExtractFunc != nil {
		return h.ExtractFunc(ctx, req)
	}
	var extractErr error
	tokens := make([]string, 0, h.Capacity)
	for _, extractor := range h.HeaderExtractors {
		res, err := extractor.Extract(ctx, req)
		if err != nil {
			extractErr = err
			continue
		}
		tokens = append(tokens, res...)
	}
	if len(tokens) == 0 {
		return ctx, extractErr
	}
	newCtx := context.WithValue(ctx, handlerKey, tokens)
	return newCtx, nil
}

func (h *JWTHandler) Parse(ctx context.Context) (any, error) {
	if h.ParseFunc != nil {
		return h.ParseFunc(ctx)
	}
	tokens := ctx.Value(handlerKey).([]string)
	for _, token := range tokens {
		payload, err := h.Parser.Parse(ctx, token)
		if err != nil {
			return nil, err
		}
		return payload, nil
	}
	return nil, nil
}
