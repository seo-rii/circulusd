//go:build linux

package agent

import (
	"context"
	"reflect"
	"slices"

	"github.com/hancomac/circulusd/internal/identity"
)

type workerdEnsureLauncher interface {
	Ensure(context.Context, WorkerdEnsureRequest) (*WorkerdShardHandle, error)
}

// WorkerdManagerLauncher binds Manager starts to one release-pinned low-level
// launcher and one construction-time argument vector. ShardSpec deliberately
// has no caller-controlled process arguments or placement generation to pass
// through this boundary.
type WorkerdManagerLauncher struct {
	launcher  workerdEnsureLauncher
	arguments []string
}

var _ Launcher = (*WorkerdManagerLauncher)(nil)

// NewWorkerdManagerLauncher constructs the narrow production Manager adapter.
func NewWorkerdManagerLauncher(launcher *WorkerdProcessLauncher, arguments []string) (*WorkerdManagerLauncher, error) {
	return newWorkerdManagerLauncher(launcher, arguments)
}

func newWorkerdManagerLauncher(launcher workerdEnsureLauncher, arguments []string) (*WorkerdManagerLauncher, error) {
	if launcher == nil {
		return nil, ErrInvalidConfig
	}
	value := reflect.ValueOf(launcher)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, ErrInvalidConfig
		}
	}
	return &WorkerdManagerLauncher{
		launcher:  launcher,
		arguments: slices.Clone(arguments),
	}, nil
}

// Start validates Manager-owned process identity and forwards only the fixed
// release arguments plus the shard identity to the low-level Ensure boundary.
func (launcher *WorkerdManagerLauncher) Start(ctx context.Context, spec ShardSpec) (ShardProcess, error) {
	if ctx == nil || launcher == nil || launcher.launcher == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if spec.AgentInstanceID.Kind() != identity.Process || spec.ShardID == "" || spec.ShardGeneration == 0 {
		return nil, ErrInvalidRequest
	}
	handle, err := launcher.launcher.Ensure(ctx, WorkerdEnsureRequest{
		AgentInstanceID: spec.AgentInstanceID,
		ShardID:         spec.ShardID,
		ShardGeneration: spec.ShardGeneration,
		Arguments:       slices.Clone(launcher.arguments),
	})
	if err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, ErrInvalidConfig
	}
	if handle.AgentInstanceID() != spec.AgentInstanceID ||
		handle.ShardID() != spec.ShardID ||
		handle.ShardGeneration() != spec.ShardGeneration {
		return handle, ErrInvalidConfig
	}
	return handle, nil
}
