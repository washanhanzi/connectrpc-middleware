# connectrpc-middleware

## auth interceptor

used with caution, still in development

```go
//default jwt.MapClaims
authInterceptor, err := NewAuthInterceptor(
	WithDefaultBeearerExtractorAndParser([]byte("secret")),
)
//custom claims
authInterceptor, err := NewAuthInterceptor(
	WithDefaultBearerExtractor(false),
	WithCustomJWTClaimsParser([]byte("secret"), func(ctx context.Context) jwt.Claims {
		return &jwtCustomClaims{}
	}),
)
//enable the interceptor for unary and stream handler
authInterceptor, err := NewAuthInterceptor(
	WithDefaultBearerExtractor(true),
	WithCustomJWTClaimsParser([]byte("secret"), func(ctx context.Context) jwt.Claims {
		return &jwtCustomClaims{}
	}),
)
```

## TODO

- tests for cookie
- test for stream handler and client
- test for kid field

## refs

- [echo-jwt](https://github.com/labstack/echo-jwt)
- [connectrpc](https://github.com/connectrpc/connect-go)
