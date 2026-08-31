package workerd

import (
	"reflect"
	"strings"
	"testing"
)

func TestResourceQualificationArgumentsAreFixedAndCanonical(t *testing.T) {
	t.Parallel()

	arguments, err := resourceQualificationArguments("/run/circulusd/workerd-fixture")
	if err != nil {
		t.Fatalf("resourceQualificationArguments() error = %v", err)
	}
	want := []string{
		"serve",
		"--experimental",
		"-I/run/circulusd/workerd-fixture",
		"/run/circulusd/workerd-fixture/phase0-resource.capnp",
	}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("resourceQualificationArguments() = %#v, want %#v", arguments, want)
	}
	arguments[0] = "caller-mutated"
	repeated, err := resourceQualificationArguments("/run/circulusd/workerd-fixture")
	if err != nil {
		t.Fatalf("resourceQualificationArguments(repeated) error = %v", err)
	}
	if !reflect.DeepEqual(repeated, want) {
		t.Fatalf("resourceQualificationArguments(repeated) = %#v, want fresh %#v", repeated, want)
	}
}

func TestResourceQualificationArgumentsRejectUnsafeFixtureDirectories(t *testing.T) {
	t.Parallel()

	for name, directory := range map[string]string{
		"empty":    "",
		"relative": "fixture",
		"unclean":  "/run/circulusd/../fixture",
		"root":     "/",
		"nul":      "/run/circulusd/fixture\x00forged",
		"too long": "/" + strings.Repeat("a", 128),
	} {
		name, directory := name, directory
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if arguments, err := resourceQualificationArguments(directory); err == nil || arguments != nil {
				t.Fatalf("resourceQualificationArguments(%q) = %#v, %v", directory, arguments, err)
			}
		})
	}
}
