package grpc

import (
	"context"
	"guard"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	mem "guard/memory"
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

func TestExtractBearerToken_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() context.Context
		wantErr bool
	}{
		{
			name: "no metadata",
			setup: func() context.Context {
				return context.Background()
			},
			wantErr: true,
		},
		{
			name: "empty authorization",
			setup: func() context.Context {
				md := metadata.Pairs("authorization", "")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantErr: true,
		},
		{
			name: "short header",
			setup: func() context.Context {
				md := metadata.Pairs("authorization", "Bear")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantErr: true,
		},
		{
			name: "bearer with no token",
			setup: func() context.Context {
				md := metadata.Pairs("authorization", "Bearer ")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantErr: true,
		},
		{
			name: "case sensitive prefix",
			setup: func() context.Context {
				md := metadata.Pairs("authorization", "bearer token")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			_, err := ExtractBearerToken(ctx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestChainUnaryInterceptors(t *testing.T) {
	var callOrder []string

	interceptor1 := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		callOrder = append(callOrder, "interceptor1")
		return handler(ctx, req)
	}

	interceptor2 := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		callOrder = append(callOrder, "interceptor2")
		return handler(ctx, req)
	}

	chained := ChainUnaryInterceptors(interceptor1, interceptor2)

	_, err := chained(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		callOrder = append(callOrder, "handler")
		return nil, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedOrder := []string{"interceptor1", "interceptor2", "handler"}
	if len(callOrder) != len(expectedOrder) {
		t.Fatalf("call order length=%d want=%d", len(callOrder), len(expectedOrder))
	}

	for i, expected := range expectedOrder {
		if callOrder[i] != expected {
			t.Fatalf("call order[%d]=%s want=%s", i, callOrder[i], expected)
		}
	}
}

func TestChainUnaryInterceptors_Empty(t *testing.T) {
	chained := ChainUnaryInterceptors()

	handlerCalled := false
	_, err := chained(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return nil, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !handlerCalled {
		t.Fatal("handler should be called when no interceptors")
	}
}

func TestChainStreamInterceptors(t *testing.T) {
	var callOrder []string

	interceptor1 := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		callOrder = append(callOrder, "stream1")
		return handler(srv, ss)
	}

	interceptor2 := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		callOrder = append(callOrder, "stream2")
		return handler(srv, ss)
	}

	chained := ChainStreamInterceptors(interceptor1, interceptor2)

	ss := &mockServerStream{ctx: context.Background()}
	err := chained(nil, ss, &grpc.StreamServerInfo{FullMethod: "/test/Stream"}, func(srv interface{}, stream grpc.ServerStream) error {
		callOrder = append(callOrder, "handler")
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedOrder := []string{"stream1", "stream2", "handler"}
	if len(callOrder) != len(expectedOrder) {
		t.Fatalf("call order length=%d want=%d", len(callOrder), len(expectedOrder))
	}

	for i, expected := range expectedOrder {
		if callOrder[i] != expected {
			t.Fatalf("call order[%d]=%s want=%s", i, callOrder[i], expected)
		}
	}
}

func TestWithAuth(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)
	unaryAuth, streamAuth := i.WithAuth()

	// Test unary
	md := metadata.Pairs("authorization", "bearer "+pair.AccessToken)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := unaryAuth(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
		if _, ok := guard.ClaimsFromContext(c); !ok {
			t.Fatal("claims not in context")
		}
		return nil, nil
	})

	if err != nil {
		t.Fatalf("unary auth failed: %v", err)
	}

	// Test stream
	ss := &mockServerStream{ctx: ctx}
	err = streamAuth(nil, ss, &grpc.StreamServerInfo{FullMethod: "/test/Stream"}, func(srv interface{}, stream grpc.ServerStream) error {
		if _, ok := guard.ClaimsFromContext(stream.Context()); !ok {
			t.Fatal("claims not in stream context")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("stream auth failed: %v", err)
	}
}

func TestWithRole(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "pw", []string{"admin"})
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})

	adminPair, _ := svc.GenerateTokens(context.Background(), admin.ID)
	userPair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)
	adminInterceptor := i.WithRole("admin")

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{name: "admin access", token: adminPair.AccessToken, wantErr: false},
		{name: "user denied", token: userPair.AccessToken, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", "bearer "+tt.token)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			_, err := adminInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/admin/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
				return nil, nil
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestWithPermission(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "pw", []string{"admin"})
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})

	adminPair, _ := svc.GenerateTokens(context.Background(), admin.ID)
	userPair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)
	permInterceptor := i.WithPermission("users", "manage")

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{name: "admin access", token: adminPair.AccessToken, wantErr: false},
		{name: "user denied", token: userPair.AccessToken, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", "bearer "+tt.token)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			_, err := permInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/users/manage"}, func(c context.Context, r interface{}) (interface{}, error) {
				return nil, nil
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestAdminOnly(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "pw", []string{"admin"})
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})

	adminPair, _ := svc.GenerateTokens(context.Background(), admin.ID)
	userPair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)
	adminOnlyInterceptor := i.AdminOnly()

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{name: "admin access", token: adminPair.AccessToken, wantErr: false},
		{name: "user denied", token: userPair.AccessToken, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", "bearer "+tt.token)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			_, err := adminOnlyInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/admin/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
				return nil, nil
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestUserOrAdmin(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "pw", []string{"admin"})
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})
	guest, _ := svc.CreateUser(context.Background(), "guest", "guest@example.com", "pw", []string{"guest"})

	adminPair, _ := svc.GenerateTokens(context.Background(), admin.ID)
	userPair, _ := svc.GenerateTokens(context.Background(), user.ID)
	guestPair, _ := svc.GenerateTokens(context.Background(), guest.ID)

	i := New(svc)
	userOrAdminInterceptor := i.UserOrAdmin()

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{name: "admin access", token: adminPair.AccessToken, wantErr: false},
		{name: "user access", token: userPair.AccessToken, wantErr: false},
		{name: "guest denied", token: guestPair.AccessToken, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", "bearer "+tt.token)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			_, err := userOrAdminInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/protected/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
				return nil, nil
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestRequireAuthenticatedUser(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})

	interceptor := RequireAuthenticatedUser(svc)

	t.Run("with user context", func(t *testing.T) {
		ctx := guard.WithClaims(context.Background(), &guard.Claims{UserID: user.ID})

		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
			// Check if user is in context
			if contextUser, ok := guard.UserFromContext(c); !ok {
				t.Fatal("user not in context")
			} else if contextUser.ID != user.ID {
				t.Fatalf("wrong user in context: got %s, want %s", contextUser.ID, user.ID)
			}
			return nil, nil
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("without user context", func(t *testing.T) {
		ctx := context.Background()

		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
			return nil, nil
		})

		if err == nil {
			t.Fatal("expected error for missing user context")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("error is not a gRPC status")
		}

		if st.Code() != codes.Unauthenticated {
			t.Fatalf("status code=%v want=%v", st.Code(), codes.Unauthenticated)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		ctx := guard.WithClaims(context.Background(), &guard.Claims{UserID: "nonexistent"})

		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
			return nil, nil
		})

		if err == nil {
			t.Fatal("expected error for nonexistent user")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("error is not a gRPC status")
		}

		if st.Code() != codes.Internal {
			t.Fatalf("status code=%v want=%v", st.Code(), codes.Internal)
		}
	})
}
