package extractor

import (
	"context"
	"net/http"
	"testing"

	"github.com/test-go/testify/assert"
	middleware "github.com/washanhanzi/connectrpc-middleware"
)

type headerValuesTest struct {
	Case         string
	Header       http.Header
	Name         string
	CutPrefix    string
	ConstructErr string
	Want         []string
	Err          string
}

var headerValuesTests = []headerValuesTest{
	{
		Case:   "empty header",
		Header: http.Header{},
		Name:   "Authorization",
		Err:    errHeaderExtractorValueMissing.Error(),
	},
	{
		Case:   "empty prefix",
		Header: http.Header{"Authorization": {"xxxx"}},
		Name:   "Authorization",
		Want: []string{
			"xxxx",
		},
	},
	{
		Case:      "custom schema",
		Header:    http.Header{"Authorization": {"test xxxx"}},
		Name:      "Authorization",
		CutPrefix: "test ",
		Want:      []string{"xxxx"},
	},
	{
		Case:      "basic auth",
		Header:    http.Header{"Authorization": {"basic xxxx"}},
		Name:      "Authorization",
		CutPrefix: "basic ",
		Want:      []string{"xxxx"},
	},
	{
		Case:      "bearer auth",
		Header:    http.Header{"Authorization": {"bearer xxxx"}},
		Name:      "Authorization",
		CutPrefix: "bearer ",
		Want:      []string{"xxxx"},
	},
	{
		Case:      "case insentive",
		Header:    http.Header{"Authorization": {"BeaRer xxxx"}},
		Name:      "Authorization",
		CutPrefix: "bearer ",
		Want:      []string{"xxxx"},
	},
	{
		Case:      "config case insentive",
		Header:    http.Header{"Authorization": {"BeaRer xxxx"}},
		Name:      "Authorization",
		CutPrefix: "beARer ",
		Want:      []string{"xxxx"},
	},
	{
		Case:      "array",
		Header:    http.Header{"Authorization": {"BeaRer xxxx", "BeaRer yyyy"}},
		Name:      "Authorization",
		CutPrefix: "beARer ",
		Want:      []string{"xxxx", "yyyy"},
	},
}

func TestValuesFromHeader(t *testing.T) {
	t.Parallel()
	for _, test := range headerValuesTests {
		t.Run(test.Case, func(t *testing.T) {
			extractor := NewHeaderExtractor(test.Name, test.CutPrefix)
			result, err := extractor.Extract(context.Background(), &middleware.Request{Header: test.Header})
			if err != nil {
				assert.EqualError(t, err, test.Err)
			}
			if len(test.Want) != 0 {
				assert.EqualValues(t, test.Want, result)
			}
		})
	}
}
