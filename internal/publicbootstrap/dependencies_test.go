package publicbootstrap_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestProductionDependenciesExcludeReferenceProviders(t *testing.T) {
	command := exec.Command("go", "list", "-deps", ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, output)
	}
	forbidden := map[string]struct{}{
		"github.com/hancomac/circulusd/internal/platformapi":       {},
		"github.com/hancomac/circulusd/internal/referenceworkload": {},
		"github.com/hancomac/circulusd/internal/celldrepo":         {},
		"github.com/hancomac/circulusd/internal/fakeeffect":        {},
	}
	for _, dependency := range strings.Fields(string(output)) {
		if _, denied := forbidden[dependency]; denied {
			t.Fatalf("public production dependency graph contains reference provider package %q", dependency)
		}
	}
}
