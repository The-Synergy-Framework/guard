module guard

go 1.24

require (
	core v0.0.0
	github.com/golang-jwt/jwt/v5 v5.2.0
	golang.org/x/crypto v0.21.0
	google.golang.org/grpc v1.60.1
)

replace core => ../core

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231002182017-d307bd883b97 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
