# connectrpc-middleware

[![Go Reference](https://pkg.go.dev/badge/github.com/washanhanzi/connectrpc-middleware#section-readme.svg)](https://pkg.go.dev/github.com/washanhanzi/connectrpc-middleware#section-readme)

## auth interceptor

used with caution, still in development

```go
//default bearer token extractor and parser
//extract token from "Authorization": Bearer <token>, and parse token into jwt.MapClaim
authMiddleware, err := middleware.NewAuthMiddleware(middleware.WithDefaultBearerExtractorAndParser([]byte("secret")))
if err != nil {
	panic(err)
}
http.ListenAndServe(
	"localhost:8080",
	// Use h2c so we can serve HTTP/2 without TLS.
	h2c.NewHandler(authMiddleware.Wrap(mux), &http2.Server{}),
)
```

## TODO

- tests for cookie
- e2e test
- test for kid field

## refs

- [echo-jwt](https://github.com/labstack/echo-jwt)
- [connectrpc](https://github.com/connectrpc/connect-go)
- [connectauth](https://github.com/akshayjshah/connectauth)
