module guard

go 1.24

require (
	github.com/golang-jwt/jwt/v5 v5.2.0
	golang.org/x/crypto v0.21.0
	google.golang.org/grpc v1.60.1
	core v0.0.0
)

replace core => ../core

require github.com/stretchr/testify v1.8.4 