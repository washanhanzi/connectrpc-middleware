package middleware

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/golang-jwt/jwt/v5"
)

type jwtParser struct {
	// Signing key to validate token.
	// This is one of the three options to provide a token validation key.
	// The order of precedence is a user-defined KeyFunc, SigningKeys and SigningKey.
	// Required if neither user-defined KeyFunc nor SigningKeys is provided.
	SigningKey any
	// Signing method used to check the token's signing algorithm.
	// Optional. Default value HS256.
	SigningMethod string
	// Claims are extendable claims data defining token content. Used by default ParseTokenFunc implementation.
	// Not used if custom ParseTokenFunc is set.
	// Optional. Defaults to function returning jwt.MapClaims
	NewClaimsFunc func(c context.Context) jwt.Claims
	// KeyFunc defines a user-defined function that supplies the public key for a token validation.
	// The function shall take care of verifying the signing algorithm and selecting the proper key.
	// A user-defined KeyFunc can be useful if tokens are issued by an external party.
	// Used by default ParseTokenFunc implementation.
	//
	// When a user-defined KeyFunc is provided, SigningKey, SigningKeys, and SigningMethod are ignored.
	// This is one of the three options to provide a token validation key.
	// The order of precedence is a user-defined KeyFunc, SigningKeys and SigningKey.
	// Required if neither SigningKeys nor SigningKey is provided.
	// Default to an internal implementation verifying the signing algorithm and selecting the proper key.
	KeyFunc jwt.Keyfunc
	// Map of signing keys to validate token with kid field usage.
	// This is one of the three options to provide a token validation key.
	// The order of precedence is a user-defined KeyFunc, SigningKeys and SigningKey.
	// Required if neither user-defined KeyFunc nor SigningKey is provided.
	SigningKeys map[string]any
}

const (
	// AlgorithmHS256 is token signing algorithm
	AlgorithmHS256 = "HS256"
)

type jwtParserOpt func(*jwtParser)

func NewJWTParser(opts ...jwtParserOpt) (jwtParser, error) {
	p := jwtParser{}
	for _, o := range opts {
		o(&p)
	}

	if p.SigningMethod == "" {
		p.SigningMethod = AlgorithmHS256
	}

	if p.NewClaimsFunc == nil {
		p.NewClaimsFunc = func(context.Context) jwt.Claims {
			return jwt.MapClaims{}
		}
	}

	if p.SigningKey == nil && len(p.SigningKeys) == 0 && p.KeyFunc == nil {
		return p, errors.New("jwt parser requires signing key")
	}

	if p.KeyFunc == nil {
		p.KeyFunc = p.defaultKeyFunc
	}
	return p, nil
}

func DefaultJWTMapClaimsParser(signingKey any) Parser {
	p, _ := NewJWTParser(WithJWTMapClaims(signingKey))
	return p.ToParser()
}

func WithJWTMapClaims(signingKey any) jwtParserOpt {
	return func(p *jwtParser) {
		p.SigningKey = signingKey
		p.SigningMethod = AlgorithmHS256
		p.NewClaimsFunc = func(context.Context) jwt.Claims {
			return jwt.MapClaims{}
		}
		p.KeyFunc = p.defaultKeyFunc
	}
}

func WithSigningKey(signingKey any) jwtParserOpt {
	return func(p *jwtParser) {
		p.SigningKey = signingKey
	}
}

func WithSigningKeys(signingKeys map[string]any) jwtParserOpt {
	return func(p *jwtParser) {
		p.SigningKeys = signingKeys
	}
}

func WithSigningMethod(signingMethod string) jwtParserOpt {
	return func(p *jwtParser) {
		p.SigningMethod = signingMethod
	}
}

// WithNewClaimsFunc sets NewClaimsFunc. the newClaimsFunc must return a reference for json unmarshalling to work
func WithNewClaimsFunc(newClaimsFunc func(context.Context) jwt.Claims) jwtParserOpt {
	return func(p *jwtParser) {
		p.NewClaimsFunc = newClaimsFunc
	}
}

func WithKeyFunc(keyFunc jwt.Keyfunc) jwtParserOpt {
	return func(p *jwtParser) {
		p.KeyFunc = keyFunc
	}
}

func (j jwtParser) ToParser() Parser {
	return func(ctx context.Context, tokensMap map[string][]string) (any, error) {
		for _, tokens := range tokensMap {
			for _, token := range tokens {
				if token == "" {
					return nil, errors.New("empty jwt token")
				}
				claims := j.NewClaimsFunc(ctx)
				jwtToken, err := jwt.ParseWithClaims(token, claims, j.KeyFunc)
				if err != nil {
					return nil, errors.Mark(err, errParseToken)
				}
				if !jwtToken.Valid {
					return nil, errors.New("invalid jwt token")
				}
				return claims, nil
			}
		}
		return nil, nil
	}
}

// defaultKeyFunc creates JWTGo implementation for KeyFunc.
//
// error returns TokenError.
func (j jwtParser) defaultKeyFunc(token *jwt.Token) (any, error) {
	if token.Method.Alg() != j.SigningMethod {
		return nil, errors.Newf("unexpected jwt signing method=%v", token.Header["alg"])
	}
	if len(j.SigningKeys) == 0 {
		return j.SigningKey, nil
	}

	if kid, ok := token.Header["kid"].(string); ok {
		if key, ok := j.SigningKeys[kid]; ok {
			return key, nil
		}
	}
	return nil, errors.Newf("unexpected jwt key id=%v", token.Header["kid"])
}
