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

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockServerStream) RecvMsg(msg interface{}) error {
	return nil
}

func (m *mockServerStream) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockServerStream) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockServerStream) SetTrailer(metadata.MD) {
}

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

func TestStreamAuthInterceptor(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	user, _ := svc.CreateUser(context.Background(), "kate", "kate@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)
	stream := i.StreamAuthInterceptor()

	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{name: "valid", header: "bearer " + pair.AccessToken, wantErr: false},
		{name: "missing", header: "", wantErr: true},
		{name: "bad prefix", header: "token " + pair.AccessToken, wantErr: true},
		{name: "invalid token", header: "bearer invalid-token", wantErr: true},
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

			ss := &mockServerStream{ctx: ctx}

			err = stream(nil, ss, &grpc.StreamServerInfo{FullMethod: "/svc/Method"}, func(srv interface{}, stream grpc.ServerStream) error {
				if _, ok := guard.ClaimsFromContext(stream.Context()); !ok && !tt.wantErr {
					t.Fatalf("claims not in context")
				}
				return nil
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestInterceptor_SkipMethods(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())

	config := DefaultConfig()
	config.SkipMethods = []string{"/health/Check", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"}

	i := New(svc, config)
	unary := i.UnaryAuthInterceptor()

	tests := []struct {
		name       string
		method     string
		wantCalled bool
	}{
		{name: "skip health", method: "/health/Check", wantCalled: true},
		{name: "skip reflection", method: "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", wantCalled: true},
		{name: "protected method", method: "/user/GetProfile", wantCalled: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerCalled := false
			ctx := context.Background() // No auth metadata

			_, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: tt.method}, func(c context.Context, r interface{}) (interface{}, error) {
				handlerCalled = true
				return nil, nil
			})

			if handlerCalled != tt.wantCalled {
				t.Fatalf("handler called=%v want=%v", handlerCalled, tt.wantCalled)
			}

			if tt.wantCalled && err != nil {
				t.Fatalf("unexpected error for skipped method: %v", err)
			}
		})
	}
}

func TestInterceptor_CustomErrorHandler(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())

	customErrorHandlerCalled := false
	config := Config{
		MetadataKey: "authorization",
		TokenPrefix: "bearer ",
		ErrorHandler: func(ctx context.Context, err error) error {
			customErrorHandlerCalled = true
			return status.Error(codes.PermissionDenied, "custom error")
		},
	}

	i := New(svc, config)
	unary := i.UnaryAuthInterceptor()

	ctx := context.Background() // No auth metadata
	_, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
		return nil, nil
	})

	if !customErrorHandlerCalled {
		t.Fatal("custom error handler not called")
	}

	if err == nil {
		t.Fatal("expected error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("error is not a gRPC status")
	}

	if st.Code() != codes.PermissionDenied {
		t.Fatalf("status code=%v want=%v", st.Code(), codes.PermissionDenied)
	}

	if st.Message() != "custom error" {
		t.Fatalf("message=%s want=%s", st.Message(), "custom error")
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

func TestUnaryRoleInterceptor_Unauthorized(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())

	i := New(svc)
	roleInterceptor := i.UnaryRoleInterceptor("admin")

	// Context without user
	ctx := context.Background()

	_, err := roleInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
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
}

func TestUnaryRoleInterceptor_Forbidden(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)

	// First authenticate, then check admin role (user doesn't have admin role)
	chained := ChainUnaryInterceptors(i.UnaryAuthInterceptor(), i.UnaryRoleInterceptor("admin"))

	md := metadata.Pairs("authorization", "bearer "+pair.AccessToken)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := chained(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/admin/Method"}, func(c context.Context, r interface{}) (interface{}, error) {
		return nil, nil
	})

	if err == nil {
		t.Fatal("expected error for insufficient role")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("error is not a gRPC status")
	}

	if st.Code() != codes.PermissionDenied {
		t.Fatalf("status code=%v want=%v", st.Code(), codes.PermissionDenied)
	}
}

func TestUnaryPermissionInterceptor_Forbidden(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	i := New(svc)

	// First authenticate, then check permission (user doesn't have admin permissions)
	chained := ChainUnaryInterceptors(i.UnaryAuthInterceptor(), i.UnaryPermissionInterceptor("users", "delete"))

	md := metadata.Pairs("authorization", "bearer "+pair.AccessToken)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := chained(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/users/Delete"}, func(c context.Context, r interface{}) (interface{}, error) {
		return nil, nil
	})

	if err == nil {
		t.Fatal("expected error for insufficient permission")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("error is not a gRPC status")
	}

	if st.Code() != codes.PermissionDenied {
		t.Fatalf("status code=%v want=%v", st.Code(), codes.PermissionDenied)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MetadataKey != "authorization" {
		t.Fatalf("MetadataKey=%s want=authorization", config.MetadataKey)
	}

	if config.TokenPrefix != "bearer " {
		t.Fatalf("TokenPrefix=%s want='bearer '", config.TokenPrefix)
	}

	if len(config.SkipMethods) != 0 {
		t.Fatalf("SkipMethods should be empty by default")
	}

	if config.ErrorHandler == nil {
		t.Fatal("ErrorHandler should not be nil")
	}
}

func TestNew_WithConfig(t *testing.T) {
	svc, _ := mem.NewService(mem.DefaultConfig())

	customConfig := DefaultConfig()
	customConfig.MetadataKey = "x-auth-token"
	customConfig.TokenPrefix = "Token "
	customConfig.SkipMethods = []string{"/health/Check"}

	i := New(svc, customConfig)

	if i.config.MetadataKey != "x-auth-token" {
		t.Fatalf("MetadataKey=%s want=x-auth-token", i.config.MetadataKey)
	}

	if i.config.TokenPrefix != "Token " {
		t.Fatalf("TokenPrefix=%s want='Token '", i.config.TokenPrefix)
	}

	if len(i.config.SkipMethods) != 1 || i.config.SkipMethods[0] != "/health/Check" {
		t.Fatalf("SkipMethods=%v want=[/health/Check]", i.config.SkipMethods)
	}
}

func TestContextStream(t *testing.T) {
	originalStream := &mockServerStream{ctx: context.Background()}
	newCtx := context.WithValue(context.Background(), "test", "value")

	wrapped := &contextStream{
		ServerStream: originalStream,
		ctx:          newCtx,
	}

	if wrapped.Context() != newCtx {
		t.Fatal("wrapped stream should return the new context")
	}

	// Test that other methods are delegated
	if err := wrapped.SendMsg(nil); err != nil {
		t.Fatalf("SendMsg failed: %v", err)
	}

	if err := wrapped.SetHeader(nil); err != nil {
		t.Fatalf("SetHeader failed: %v", err)
	}
}
