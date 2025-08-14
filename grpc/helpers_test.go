package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{name: "ok", header: "Bearer abc", wantErr: false},
		{name: "missing", header: "", wantErr: true},
		{name: "bad prefix", header: "Token abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			if tt.header != "" {
				md := metadata.Pairs("authorization", tt.header)
				ctx = metadata.NewIncomingContext(context.Background(), md)
			} else {
				ctx = context.Background()
			}
			_, err := ExtractBearerToken(ctx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
