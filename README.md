# connectrpc-middleware

[![Go Reference](https://pkg.go.dev/badge/github.com/washanhanzi/connectrpc-middleware#section-readme.svg)](https://pkg.go.dev/github.com/washanhanzi/connectrpc-middleware#section-readme)

# auth middleware

## default jwt middleware

```go
middleware "github.com/washanhanzi/connectrpc-middleware"
handler "github.com/washanhanzi/connectrpc-middleware/handler"

//a default jwt handler
jwtHandler := handler.NewJWTHandler(
	//add skip, before, success, error to shim()
	handler.NewShim(),
	//no extractor specified, it default to extract token from "Authorization": Bearer <token>
	//default jwt parser, the default result is jwt.MapClaims which can be retrieved by middleware.FromContext[jwt.MapClaims](ctx)
	handler.WithJwtMapClaimsParser([]byte("secret_key")),
)
//create new middleware
authMiddleware, err := middleware.NewAuthMiddleware(middleware.WithHandler(jwtHandler))
if err != nil {
	panic(err)
}

//...

http.ListenAndServe(
	"localhost:8080",
	// Use h2c so we can serve HTTP/2 without TLS.
	h2c.NewHandler(authMiddleware.Wrap(mux), &http2.Server{}),
)
```

## skip middleware

```go
jwtHandler := handler.NewJWTHandler(
	//add skip, before, success, error to shim()
	handler.NewShim(
		//skip the middleware if the header "x-api-key" is "super-secret-key"
		handler.WithSkip(func(ctx context.Context, req *middleware.Request) bool {
			return req.Header().Get("x-api-key") == "super-secret-key"
		}),
	),
	handler.WithJwtMapClaimsParser([]byte("secret_key")),
)
```

## jwt, custom header

```go
jwtHandler := handler.NewJWTHandler(
	//add skip, before, success, error to shim()
	handler.NewShim(),
	//extract token from "Authorization": Bearer <token>
	handler.WithExtractor(extractor.JwtTokenExtractor()),
	//extract token from "X-API-KEY": key <token>
	handler.WithExtractor(extractor.NewHeaderExtractor("X-API-KEY","key ")),
	//this jwt parser will parse all the tokens from the above extractors until success
	handler.WithJwtMapClaimsParser([]byte("secret_key")),
)
```

## TODO

- tests for cookie
- test for kid field

## refs

- [echo-jwt](https://github.com/labstack/echo-jwt)
- [connectrpc](https://github.com/connectrpc/connect-go)
- [connectauth](https://github.com/akshayjshah/connectauth)
