# connectrpc-middleware

[![Go Reference](https://pkg.go.dev/badge/github.com/washanhanzi/connectrpc-middleware#section-readme.svg)](https://pkg.go.dev/github.com/washanhanzi/connectrpc-middleware#section-readme)

## auth interceptor

used with caution, still in development

```go
	//default jwt.MapClaims
	authInterceptor, err := NewAuthInterceptor(
		WithDefaultBearerExtractorAndParser([]byte("secret")),
	)

	//get the payload from context
	payload, ok := FromContext[jwt.MapClaims](ctx)

	//custom claims
	authInterceptor, err := NewAuthInterceptor(
		//extract token from "Authorization": "bearer <token>"
		WithDefaultBearerExtractor(false),
		WithCustomJWTClaimsParser([]byte("secret"), func(ctx context.Context) jwt.Claims {
			return &jwtCustomClaims{}
		}),
	)
	//get the claims from context
	claims, ok := FromContext[*jwtCustomClaims](ctx)

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

	//custom parser
	//the request contains an Authorization header with bearer token and a user-id header
	//Parser will parse the jwt claims into customPayload.jwtCustomInfo, and user-id into customPayload.userId
	type jwtCustomInfo struct {
		Name  string `json:"name"`
		Admin bool   `json:"admin"`
	}
	type jwtCustomClaims struct {
		*jwt.RegisteredClaims
		jwtCustomInfo
	}
	type customPayload struct {
		jwtCustomInfo
		UserId string
	}


	extractor, err := NewHeaderExtractor(
		WithLookupConfig("header", "Authorization", "bearer "),
		WithLookupConfig("header", "user-id", ""),
	)
	parser := func(ctx context.Context, tokensMap map[string][]string) (any, error) {
		payload := customPayload{}
		claims := jwtCustomClaims{}
		if tokens, ok := tokensMap["Authorization"]; ok {
			for _, token := range tokens {
				jwtToken, err := jwt.ParseWithClaims(token,
					&claims,
					func(token *jwt.Token) (any, error) {
						return []byte("secret"), nil
					})
				if err != nil {
					return payload, err
				}
				if !jwtToken.Valid {
					return payload, errors.New("invalid jwt token")
				}
				payload.jwtCustomInfo = claims.jwtCustomInfo
			}
		}
		if userIds, ok := tokensMap["user-id"]; ok {
			if len(userIds) != 0 {
				payload.UserId = userIds[0]
			}
		}
		return payload, nil
	}
	interceptor, err := NewAuthInterceptor(
		WithUnaryExtractor(extractor.ToUnaryExtractor()),
		WithParser(parser),
	)
	//get the payload from context
	claims, ok := FromContext[customPayload](ctx)
```

## TODO

- tests for cookie
- test for stream handler and client
- test for kid field

## refs

- [echo-jwt](https://github.com/labstack/echo-jwt)
- [connectrpc](https://github.com/connectrpc/connect-go)
