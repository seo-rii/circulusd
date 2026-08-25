package sandboxd_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/sandboxd"
)

func TestCommandNameRejectsHostPaths(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", ".", "..", "/bin/sh", "bin/sh", `C:\\bin\\sh`, "a\x00b"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := sandboxd.ParseCommandName(value); !errors.Is(err, sandboxd.ErrInvalidRequest) {
				t.Fatalf("ParseCommandName(%q) error = %v, want ErrInvalidRequest", value, err)
			}
		})
	}

	command, err := sandboxd.ParseCommandName("python3")
	if err != nil {
		t.Fatalf("ParseCommandName() error = %v", err)
	}
	if command.String() != "python3" {
		t.Fatalf("CommandName.String() = %q", command.String())
	}
}

func TestWorkspacePathIsOpaqueAndWorkspaceRelative(t *testing.T) {
	t.Parallel()

	root, err := sandboxd.ParseWorkspacePath("")
	if err != nil {
		t.Fatalf("ParseWorkspacePath(root) error = %v", err)
	}
	if root.String() != "." {
		t.Fatalf("root WorkspacePath = %q, want .", root.String())
	}

	for _, value := range []string{"/tmp", "../tmp", "a/../b", "a//b", "a/./b", "a/", "a\x00b"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := sandboxd.ParseWorkspacePath(value); !errors.Is(err, sandboxd.ErrInvalidRequest) {
				t.Fatalf("ParseWorkspacePath(%q) error = %v, want ErrInvalidRequest", value, err)
			}
		})
	}

	path, err := sandboxd.ParseWorkspacePath("project/src")
	if err != nil {
		t.Fatalf("ParseWorkspacePath() error = %v", err)
	}
	if path.String() != "project/src" {
		t.Fatalf("WorkspacePath.String() = %q", path.String())
	}
}

func TestSpawnRequestHasNoRawAuthorityOrMountFields(t *testing.T) {
	t.Parallel()

	typeOfRequest := reflect.TypeOf(sandboxd.SpawnRequest{})
	for i := range typeOfRequest.NumField() {
		field := typeOfRequest.Field(i)
		lowerName := strings.ToLower(field.Name)
		for _, forbidden := range []string{
			"tenant",
			"userid",
			"workspaceid",
			"sandboxid",
			"hostpath",
			"mount",
			"device",
		} {
			if strings.Contains(lowerName, forbidden) {
				t.Fatalf("SpawnRequest exposes forbidden field %q", field.Name)
			}
		}
	}

	workingDirectory, ok := typeOfRequest.FieldByName("WorkingDirectory")
	if !ok {
		t.Fatal("SpawnRequest is missing WorkingDirectory")
	}
	if workingDirectory.Type.Kind() == reflect.String {
		t.Fatal("SpawnRequest.WorkingDirectory must not be a raw string")
	}
	executable, ok := typeOfRequest.FieldByName("Command")
	if !ok {
		t.Fatal("SpawnRequest is missing Command")
	}
	if executable.Type.Kind() == reflect.String {
		t.Fatal("SpawnRequest.Command must not be a raw string")
	}
}
