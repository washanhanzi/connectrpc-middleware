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
	// Signing method used to check the token's signing algorithm.
	// Optional. Default value HS256.
	SigningMethod string
	// NewClaimsFunc is used during parsing the token, it must return a reference for json unmarshalling to work
	// Default to function returning jwt.MapClaims
	NewClaimsFunc func(c context.Context) jwt.Claims
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

	// set default singing method
	if p.SigningMethod == "" {
		p.SigningMethod = AlgorithmHS256
	}

	//set default claims func
	if p.NewClaimsFunc == nil {
		p.NewClaimsFunc = func(context.Context) jwt.Claims {
			return jwt.MapClaims{}
		}
	}

	//check for signing key
	if p.SigningKey == nil && len(p.SigningKeys) == 0 && p.KeyFunc == nil {
		return p, errors.New("jwt parser requires signing key")
	}

	//if singing key is provided, set default key func
	if p.KeyFunc == nil {
		if len(p.SigningKeys) != 0 {
			p.KeyFunc = p.defaultKeyFuncForSigningKeys
			return p, nil
		}
		p.KeyFunc = p.defaultKeyFuncForSigningKey
	}
	return p, nil
}

// DefaultJWTMapClaimsParser returns a jwtParser with default jwt.MapClaims and signingMethod
func DefaultJWTMapClaimsParser(signingKey any) Parser {
	p, _ := NewJWTParser(WithJWTMapClaims(signingKey))
	return p.ToParser()
}

// WithJWTMapClaims returns a jwtParser with default jwt.MapClaims and signingMethod
func WithJWTMapClaims(signingKey any) jwtParserOpt {
	return func(p *jwtParser) {
		p.SigningKey = signingKey
		p.SigningMethod = AlgorithmHS256
		p.NewClaimsFunc = func(context.Context) jwt.Claims {
			return jwt.MapClaims{}
		}
		p.KeyFunc = p.defaultKeyFuncForSigningKey
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
	return func(ctx context.Context, extractedHeader ExtractedHeader) (any, error) {
		for _, values := range extractedHeader {
			for _, v := range values {
				if v == "" {
					return nil, errors.New("empty jwt token")
				}
				claims := j.NewClaimsFunc(ctx)
				jwtToken, err := jwt.ParseWithClaims(v, claims, j.KeyFunc)
				if err != nil {
					return nil, err
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

func (j jwtParser) ParserJWT(token string, claims jwt.Claims) error {
	if token == "" {
		return errors.New("empty jwt token")
	}
	jwtToken, err := jwt.ParseWithClaims(token, claims, j.KeyFunc)
	if err != nil {
		return err
	}
	if !jwtToken.Valid {
		return errors.New("invalid jwt token")
	}
	return nil
}

func (j jwtParser) defaultKeyFuncForSigningKeys(token *jwt.Token) (any, error) {
	if token.Method.Alg() != j.SigningMethod {
		return nil, errors.Newf("unexpected jwt signing method=%v", token.Header["alg"])
	}

	if kid, ok := token.Header["kid"].(string); ok {
		if key, ok := j.SigningKeys[kid]; ok {
			return key, nil
		}
	}
	return nil, errors.Newf("unexpected jwt key id=%v", token.Header["kid"])
}

func (j jwtParser) defaultKeyFuncForSigningKey(token *jwt.Token) (any, error) {
	if token.Method.Alg() != j.SigningMethod {
		return nil, errors.Newf("unexpected jwt signing method=%v", token.Header["alg"])
	}
	return j.SigningKey, nil
}
