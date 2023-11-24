package middleware

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/test-go/testify/assert"
)

var (
	token       = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	validKey    = []byte("secret")
	invalidKey  = []byte("invalid-key")
	validAuth   = "Bearer " + token
	invalidAuth = "Bearer invalid-token"
)

type jwtCustomInfo struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}
type customClaims struct {
	jwt.RegisteredClaims
	jwtCustomInfo
}

var jwtParserTests = []struct {
	Case      string
	Parser    func(t *testing.T) Parser
	Validate  func(t *testing.T, payload any)
	Token     string
	ParserErr string
}{
	{
		Case: "Empty singing key",
		Parser: func(t *testing.T) Parser {
			_, err := NewJWTParser(WithSigningMethod("RS256"))
			assert.EqualError(t, err, "jwt parser requires signing key")
			return nil
		},
	},
	{
		Case: "Empty lookup configs",
		Parser: func(t *testing.T) Parser {
			_, err := NewJWTParser()
			assert.EqualError(t, err, "jwt parser requires signing key")
			return nil
		},
	},
	{
		Case: "Unexpected signing method",
		Parser: func(t *testing.T) Parser {
			parser, err := NewJWTParser(WithSigningKey(validKey), WithSigningMethod("RS256"))
			assert.Nil(t, err)
			return parser.ToParser()
		},
		Token:     token,
		ParserErr: "token is unverifiable: error while executing keyfunc: unexpected jwt signing method=HS256",
	},
	{
		Case: "Invalid key",
		Parser: func(t *testing.T) Parser {
			parser, err := NewJWTParser(WithSigningKey(invalidKey))
			assert.Nil(t, err)
			return parser.ToParser()
		},
		Token:     token,
		ParserErr: "token signature is invalid: signature is invalid",
	},
	{
		Case: "Valid jwt",
		Parser: func(t *testing.T) Parser {
			parser, err := NewJWTParser(WithSigningKey(validKey))
			assert.Nil(t, err)
			return parser.ToParser()
		},
		Token:     token,
		ParserErr: "",
		Validate: func(t *testing.T, payload any) {
			assert.Equal(t, "1234567890", payload.(jwt.MapClaims)["sub"])
			assert.Equal(t, "John Doe", payload.(jwt.MapClaims)["name"])
			assert.Equal(t, true, payload.(jwt.MapClaims)["admin"])
		},
	},
	{
		Case: "Valid jwt",
		Parser: func(t *testing.T) Parser {
			parser, err := NewJWTParser(WithSigningKey(validKey))
			assert.Nil(t, err)
			return parser.ToParser()
		},
		Token:     token,
		ParserErr: "",
		Validate: func(t *testing.T, payload any) {
			assert.Equal(t, "1234567890", payload.(jwt.MapClaims)["sub"])
			assert.Equal(t, "John Doe", payload.(jwt.MapClaims)["name"])
			assert.Equal(t, true, payload.(jwt.MapClaims)["admin"])
		},
	},
	{
		Case: "Valid jwt with custom claims",
		Parser: func(t *testing.T) Parser {
			parser, err := NewJWTParser(WithSigningKey(validKey), WithNewClaimsFunc(
				func(context.Context) jwt.Claims {
					return &customClaims{}
				},
			))
			assert.Nil(t, err)
			return parser.ToParser()
		},
		Token:     token,
		ParserErr: "",
		Validate: func(t *testing.T, payload any) {
			assert.Equal(t, "1234567890", payload.(*customClaims).Subject)
			assert.Equal(t, "John Doe", payload.(*customClaims).Name)
			assert.Equal(t, true, payload.(*customClaims).Admin)
		},
	},
}

func Test(t *testing.T) {
	for _, tt := range jwtParserTests {
		p := tt.Parser(t)
		if p == nil {
			continue
		}
		payload, err := p(context.Background(), tt.Token)
		if tt.ParserErr != "" {
			assert.EqualError(t, err, tt.ParserErr)
		} else {
			assert.Nil(t, err)
		}
		if payload != nil {
			tt.Validate(t, payload)
		}

	}
}
