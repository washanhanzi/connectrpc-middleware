package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/cockroachdb/errors"
)

type ExtractedHeader map[string][]string

func newExtractedHeader(capacity int) ExtractedHeader {
	return make(map[string][]string, capacity)
}

func (h ExtractedHeader) Set(key string, values []string) {
	h[key] = values
}

func (h ExtractedHeader) Get(key string) []string {
	return h[key]
}

type HeaderExtractor struct {
	configs []LookupConfig
}

type TokenSource string

const HeaderAuthorization = "Authorization"

const (
	TokenSourceHeader TokenSource = "header"
	TokenSourceCookie TokenSource = "cookie"
)

type LookupConfig struct {
	Source    TokenSource
	Name      string
	CutPrefix string // Optional, used only if Source is "header"
}

type headerExtractorOpt func(*HeaderExtractor)

func NewHeaderExtractor(opts ...headerExtractorOpt) (HeaderExtractor, error) {
	e := HeaderExtractor{}
	for _, opt := range opts {
		opt(&e)
	}
	if len(e.configs) == 0 {
		return e, errors.New("no lookup config provided")
	}
	return e, nil
}

func WithLookupConfig(source, name, cutPrefix string) headerExtractorOpt {
	return func(e *HeaderExtractor) {
		if len(e.configs) == 0 {
			e.configs = []LookupConfig{{Source: TokenSource(source), Name: name, CutPrefix: cutPrefix}}
		} else {
			e.configs = append(e.configs, LookupConfig{Source: TokenSource(source), Name: name, CutPrefix: cutPrefix})
		}
	}
}

func WithLookupConfigs(configs ...LookupConfig) headerExtractorOpt {
	return func(e *HeaderExtractor) {
		if len(e.configs) == 0 {
			e.configs = configs
		} else {
			e.configs = append(e.configs, configs...)
		}
	}
}

func DefaultBearerTokenExtractor() HeaderExtractor {
	return HeaderExtractor{
		configs: []LookupConfig{
			{
				Source:    TokenSourceHeader,
				Name:      HeaderAuthorization,
				CutPrefix: "Bearer ",
			},
		},
	}
}

func DefaultBasicExtractor() HeaderExtractor {
	return HeaderExtractor{
		configs: []LookupConfig{
			{
				Source:    TokenSourceHeader,
				Name:      HeaderAuthorization,
				CutPrefix: "Basic ",
			},
		},
	}
}

func (e HeaderExtractor) ToExtractor() Extractor {
	return func(ctx context.Context, req *Request) (ExtractedHeader, error) {
		extracted := newExtractedHeader(len(e.configs))
		var lastErr error
		for _, c := range e.configs {
			switch c.Source {
			case TokenSourceHeader:
				values := req.Header.Values(c.Name)
				extractedValues, err := ValuesFromHeader(values, c.CutPrefix)
				if err != nil {
					lastErr = err
				}
				extracted.Set(c.Name, extractedValues)
			case TokenSourceCookie:
				cookiesRaw := req.Header.Get(string(TokenSourceCookie))
				values, err := ValuesFromCookie(c.Name, cookiesRaw)
				if err != nil {
					lastErr = err
				}
				extracted.Set(c.Name, values)
			}
		}
		if len(extracted) == 0 {
			return nil, lastErr
		}
		return extracted, nil
	}
}

var errHeaderExtractorValueMissing = errors.New("missing value in request header")
var errHeaderExtractorValueInvalid = errors.New("invalid value in request header")

// ValuesFromHeader returns a functions that extracts values from the request header.
// valuePrefix is parameter to remove first part (prefix) of the extracted value. This is useful if header value has static
// prefix like `Authorization: <auth-scheme> <authorisation-parameters>` where part that we want to remove is `<auth-scheme> `
// note the space at the end. In case of basic authentication `Authorization: Basic <credentials>` prefix we want to remove
// is `Basic `. In case of JWT tokens `Authorization: Bearer <token>` prefix is `Bearer `.
// If prefix is left empty the whole value is returned.
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

// FromRawCookies takes a raw cookie string and returns a slice of *http.Cookie
func FromRawCookies(rawCookies string) []*http.Cookie {
	header := http.Header{}
	header.Add("Cookie", rawCookies)
	request := http.Request{Header: header}
	return request.Cookies()
}

// extractorLimit is arbitrary number to limit values extractor can return. this limits possible resource exhaustion
// attack vector
const extractorLimit = 20

var errCookieExtractorValueMissing = errors.New("missing value in cookies")

// ValuesFromCookie returns a function that extracts values from the named cookie.
func ValuesFromCookie(name, cookiesRaw string) ([]string, error) {
	if len(cookiesRaw) == 0 {
		return nil, errCookieExtractorValueMissing
	}
	cookies := FromRawCookies(cookiesRaw)

	result := make([]string, 0, 10)
	for i, cookie := range cookies {
		if name == cookie.Name {
			result = append(result, cookie.Value)
			if i >= extractorLimit-1 {
				break
			}
		}
	}
	if len(result) == 0 {
		return nil, errCookieExtractorValueMissing
	}
	return result, nil
}
