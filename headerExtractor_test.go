package middleware

import (
	"context"
	"net/http"
	"testing"

	"github.com/test-go/testify/assert"
)

type headerValuesTest struct {
	Case         string
	Header       map[string]string
	Configs      []LookupConfig
	ConstructErr string
	Want         map[string][]string
	Err          string
}

var headerValuesTests = []headerValuesTest{
	{
		Case:         "invalid config source",
		Configs:      []LookupConfig{{Source: "body", Name: "Authorization"}},
		ConstructErr: `invalid config source "body", only "header" and "cookie" are supported`,
		Err:          errHeaderExtractorValueMissing.Error(),
	},
	{
		Case:    "invalid header",
		Configs: []LookupConfig{{Source: "header", Name: "Authorization"}},
		Err:     errHeaderExtractorValueMissing.Error(),
	},
	{
		Case:    "empty header",
		Configs: []LookupConfig{{Source: "header", Name: "Authorization"}},
		Err:     errHeaderExtractorValueMissing.Error(),
	},
	{
		Case:    "empty prefix",
		Header:  map[string]string{"Authorization": "xxxx"},
		Configs: []LookupConfig{{Source: "header", Name: "Authorization"}},
		Want: map[string][]string{
			"Authorization": {"xxxx"},
		},
	},
	{
		Case:    "custom schema",
		Header:  map[string]string{"Authorization": "test xxxx"},
		Configs: []LookupConfig{{Source: "header", Name: "Authorization", CutPrefix: "test "}},
		Want: map[string][]string{
			"Authorization": {"xxxx"},
		},
	},
	{
		Case:    "basic auth",
		Header:  map[string]string{"Authorization": "basic xxxx"},
		Configs: []LookupConfig{{Source: "header", Name: "Authorization", CutPrefix: "basic "}},
		Want: map[string][]string{
			"Authorization": {"xxxx"},
		},
	},
	{
		Case:    "bearer auth",
		Header:  map[string]string{"Authorization": "bearer xxxx"},
		Configs: []LookupConfig{{Source: "header", Name: "Authorization", CutPrefix: "bearer "}},
		Want: map[string][]string{
			"Authorization": {"xxxx"},
		},
	},
	{
		Case:    "case insentive",
		Header:  map[string]string{"Authorization": "BeaRer xxxx"},
		Configs: []LookupConfig{{Source: "header", Name: "Authorization", CutPrefix: "bearer "}},
		Want: map[string][]string{
			"Authorization": {"xxxx"},
		},
	},
	{
		Case:    "config case insentive",
		Header:  map[string]string{"Authorization": "BeaRer xxxx"},
		Configs: []LookupConfig{{Source: "header", Name: "AuthorizAtion", CutPrefix: "beARer "}},
		Want: map[string][]string{
			"AuthorizAtion": {"xxxx"},
		},
	},
	{
		Case: "multiple values",
		Header: map[string]string{
			"Authorization": "BeaRer xxxx",
			"user-name":     "John Doe",
		},
		Configs: []LookupConfig{
			{Source: "header", Name: "Authorization", CutPrefix: "bearer "},
			{Source: "header", Name: "user-name", CutPrefix: ""},
		},
		Want: map[string][]string{
			"Authorization": {"xxxx"},
			"user-name":     {"John Doe"},
		},
	},
}

func TestValuesFromHeader(t *testing.T) {
	t.Parallel()
	for _, test := range headerValuesTests {
		t.Run(test.Case, func(t *testing.T) {
			headerExtractor, err := NewHeaderExtractor(WithLookupConfigs(test.Configs...))
			if test.ConstructErr == "" {
				assert.Nil(t, err)
			} else {
				assert.EqualError(t, err, test.ConstructErr)
			}
			extracor := headerExtractor.ToExtractor()
			headers := http.Header{}
			for k, v := range test.Header {
				headers.Add(k, v)
			}
			result, err := extracor(context.Background(), &Request{Header: headers})
			if err != nil {
				if !assert.EqualError(t, err, test.Err) {
					t.Errorf("case: %v, expected error %v, got error %v", test.Case, test.Err, err)
				}
			}
			if len(test.Want) != 0 {
				for k, v := range test.Want {
					assert.EqualValues(t, v, result[k])
				}
			}
		})
	}
}
