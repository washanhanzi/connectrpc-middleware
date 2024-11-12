package extractor

import (
	"context"
	"net/http"

	"github.com/cockroachdb/errors"
	middleware "github.com/washanhanzi/connectrpc-middleware"
)

type CookieLookup struct {
	Name string
}

func NewCookieExtractor(name string) *CookieLookup {
	return &CookieLookup{Name: name}
}

func (l *CookieLookup) Extract(ctx context.Context, req *middleware.Request) ([]string, error) {
	cookiesRaw := req.Header.Get("cookie")
	values, err := ValuesFromCookie(l.Name, cookiesRaw)
	if err != nil {
		return nil, err
	}
	return values, nil
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
