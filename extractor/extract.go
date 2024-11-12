package extractor

import (
	"context"

	middleware "github.com/washanhanzi/connectrpc-middleware"
)

type HeaderExtractor interface {
	Extract(ctx context.Context, req *middleware.Request) ([]string, error)
	Key() string
}
