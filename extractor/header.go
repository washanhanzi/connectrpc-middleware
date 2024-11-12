package extractor

import (
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	middleware "github.com/washanhanzi/connectrpc-middleware"
)

type HeaderLookup struct {
	Name      string
	CutPrefix string // Optional, used only if Source is "header"
}

func NewHeaderExtractor(name, cutPrefix string) *HeaderLookup {
	return &HeaderLookup{Name: name, CutPrefix: cutPrefix}
}

func JwtTokenExtractor() *HeaderLookup {
	return &HeaderLookup{Name: "Authorization", CutPrefix: "Bearer "}
}

func BasicTokenExtractor() *HeaderLookup {
	return &HeaderLookup{Name: "Authorization", CutPrefix: "Basic "}
}

func (l *HeaderLookup) Key() string {
	return l.Name
}

func (l *HeaderLookup) Extract(ctx context.Context, req *middleware.Request) ([]string, error) {
	res, err := ValuesFromHeader(req.Header.Values(l.Name), l.CutPrefix)
	if err != nil {
		return nil, err
	}
	return res, nil
}

var errHeaderExtractorValueMissing = errors.New("missing value in request header")
var errHeaderExtractorValueInvalid = errors.New("invalid value in request header")

// ValuesFromHeader take http.Request.Header.Values and a prefix as input
// return a slice of string without the prefix
// when values is empty, return errHeaderExtractorValueMissing
// when prefix is empty, return the input values, keep the http.Request.Header.Values backing array if there is one
// when prefix is not empty, return a new slice of values without the prefix
func ValuesFromHeader(values []string, valuePrefix string) ([]string, error) {
	if len(values) == 0 {
		return nil, errHeaderExtractorValueMissing
	}

	if len(valuePrefix) == 0 {
		return values, nil
	}

	prefixLen := len(valuePrefix)
	result := make([]string, 0, len(values))
	for i, value := range values {
		if i >= extractorLimit {
			break
		}
		if len(value) > prefixLen && strings.EqualFold(value[:prefixLen], valuePrefix) {
			result = append(result, value[prefixLen:])
		}
	}

	if len(result) == 0 {
		return nil, errHeaderExtractorValueInvalid
	}
	return result, nil
}
