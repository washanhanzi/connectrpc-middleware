package middleware

import (
	"context"
	"reflect"
	"testing"

	"connectrpc.com/connect"
	"github.com/test-go/testify/assert"
	pingv1 "github.com/washanhanzi/connectrpc-middleware/example/gen/ping/v1"
)

type headerValuesTest struct {
	Case      string
	GotReq    func() *connect.Request[pingv1.PingRequest]
	Extractor func(*testing.T) HeaderExtractor
	Want      []string
	Err       string
}

var headerValuesTests = []headerValuesTest{
	{
		Case: "invalid header",
		GotReq: func() *connect.Request[pingv1.PingRequest] {
			return connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
		},
		Extractor: func(t *testing.T) HeaderExtractor { return DefaultBasicExtractor() },
		Err:       errHeaderExtractorValueMissing.Error(),
	},
	{
		Case: "empty header",
		GotReq: func() *connect.Request[pingv1.PingRequest] {
			return connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
		},
		Extractor: func(t *testing.T) HeaderExtractor { return DefaultBasicExtractor() },
		Err:       errHeaderExtractorValueMissing.Error(),
	},
	{
		Case: "empty prefix",
		GotReq: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set("Authorization", "xxxx")
			return req
		},
		Extractor: func(t *testing.T) HeaderExtractor {
			ex, _ := NewHeaderExtractor(WithLookupConfig("header", "Authorization", ""))
			return ex
		},
		Want: []string{"xxxx"},
	},
	{
		Case: "custom schema",
		GotReq: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set("Authorization", "test xxxx")
			return req
		},
		Extractor: func(t *testing.T) HeaderExtractor {
			ee, err := NewHeaderExtractor(WithLookupConfig(string(TokenSourceHeader), HeaderAuthorization, "test "))
			assert.Nil(t, err)
			return ee
		},
		Want: []string{"xxxx"},
	},
	{
		Case: "basic auth",
		GotReq: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set("Authorization", "basic xxxx")
			return req
		},
		Extractor: func(t *testing.T) HeaderExtractor { return DefaultBasicExtractor() },
		Want:      []string{"xxxx"},
	},
	{
		Case: "bearer auth",
		GotReq: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set("Authorization", "bearer xxxx")
			return req
		},
		Extractor: func(t *testing.T) HeaderExtractor { return DefaultBearerTokenExtractor() },
		Want:      []string{"xxxx"},
	},
	{
		Case: "case insentive",
		GotReq: func() *connect.Request[pingv1.PingRequest] {
			req := connect.NewRequest[pingv1.PingRequest](&pingv1.PingRequest{})
			req.Header().Set("Authorization", "bearer xxxx")
			return req
		},
		Extractor: func(t *testing.T) HeaderExtractor { return DefaultBearerTokenExtractor() },
		Want:      []string{"xxxx"},
	},
}

func TestValuesFromHeader(t *testing.T) {
	t.Parallel()
	for _, test := range headerValuesTests {
		t.Run(test.Case, func(t *testing.T) {
			u := test.Extractor(t).ToUnaryExtractor()
			result, err := u(context.Background(), test.GotReq())
			if err != nil {
				if !assert.EqualError(t, err, test.Err) {
					t.Errorf("case: %v, expected error %v, got error %v", test.Case, test.Err, err)
				}
			}
			if !reflect.DeepEqual(result, test.Want) {
				t.Errorf("case: %v, expected result %v, got %v", test.Case, test.Want, result)
			}
		})
	}
}
