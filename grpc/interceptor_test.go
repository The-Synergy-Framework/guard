package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"guard"
	mem "guard/memory"
)

func TestUnaryAuthInterceptor(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	user, _ := svc.CreateUser(context.Background(), "kate", "kate@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)
	unary := i.UnaryAuthInterceptor()

	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{name: "valid", header: "bearer " + pair.AccessToken, wantErr: false},
		{name: "missing", header: "", wantErr: true},
		{name: "bad prefix", header: "token " + pair.AccessToken, wantErr: true},
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

			_, err = unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
				if _, ok := guard.ClaimsFromContext(c); !ok && !tt.wantErr {
					t.Fatalf("claims not in context")
				}
				return nil, nil
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestUnaryRoleAndPermission(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	user, _ := svc.CreateUser(context.Background(), "u", "u@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)

	unary := ChainUnaryInterceptors(i.UnaryAuthInterceptor(), i.UnaryRoleInterceptor("user"))
	md := metadata.Pairs("authorization", "bearer "+pair.AccessToken)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	if _, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(c context.Context, r interface{}) (interface{}, error) { return nil, nil }); err != nil {
		t.Fatalf("role chain failed: %v", err)
	}

	unaryPerm := ChainUnaryInterceptors(i.UnaryAuthInterceptor(), i.UnaryPermissionInterceptor("profile", "read"))
	if _, err := unaryPerm(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(c context.Context, r interface{}) (interface{}, error) { return nil, nil }); err != nil {
		t.Fatalf("perm chain failed: %v", err)
	}
}
