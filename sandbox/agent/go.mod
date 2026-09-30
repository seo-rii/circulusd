module circulusd-test/sandbox/agent

go 1.25.0

require (
	connectrpc.com/connect v1.19.1
	github.com/hancomac/circulusd v0.0.0
	golang.org/x/sys v0.41.0
	google.golang.org/protobuf v1.36.10
)

replace github.com/hancomac/circulusd => ../../../circulusd
