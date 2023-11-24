# connectrpc-middleware

## auth interceptor

used with caution, still in development

```go
	//default jwt.MapClaims
	authInterceptor, err := NewAuthInterceptor(
		WithDefaultBearerExtractorAndParser([]byte("secret")),
	)

	//custom claims
	authInterceptor, err := NewAuthInterceptor(
		//extract token from "Authorization": "bearer <token>"
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

	//basic token
	//extract token from "Authorization": "basic <token>"
	basicExtractor := DefaultBasicExtractor()
	authInterceptor, err := NewAuthInterceptor(
		WithUnaryExtractor(basicExtractor.ToUnaryExtractor()),
		WithStreamExtractor(basicExtractor.ToStreamExtractor()),
		WithCustomJWTClaimsParser([]byte("secret"), func(ctx context.Context) jwt.Claims {
			return &jwtCustomClaims{}
		}),
	)

	//custom token header
	//extract token from "auth": "mytoken <token>"
	//and token from "auth": "mytoken <token>"
	customExtractor, err := NewHeaderExtractor(
		WithLookupConfig("header", "auth", "mytoken "),
		WithLookupConfig("header", "Authorization", "bearer "),
	)
	authInterceptor, err := NewAuthInterceptor(
		WithUnaryExtractor(customExtractor.ToUnaryExtractor()),
		WithStreamExtractor(customExtractor.ToStreamExtractor()),
		WithCustomJWTClaimsParser([]byte("secret"), func(ctx context.Context) jwt.Claims {
			return &jwtCustomClaims{}
		}),
	)

	//skip unary handler
	customExtractor, err := NewHeaderExtractor(
		WithLookupConfig("header", "auth", "mytoken "),
		WithLookupConfig("header", "Authorization", "bearer "),
	)
	authInterceptor, err := NewAuthInterceptor(
		WithStreamExtractor(customExtractor.ToStreamExtractor()),
		WithCustomJWTClaimsParser([]byte("secret"), func(ctx context.Context) jwt.Claims {
			return &jwtCustomClaims{}
		}),
		WithNoUnaryHandler(),
	)

	//ignore error
	authInterceptor, err := NewAuthInterceptor(
		WithDefaultBearerExtractorAndParser([]byte("secret")),
		WithIgnoreUnaryError(),
	)
```

## TODO

- tests for cookie
- test for stream handler and client
- test for kid field

## refs

- [echo-jwt](https://github.com/labstack/echo-jwt)
- [connectrpc](https://github.com/connectrpc/connect-go)
