package workerd

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const maximumResourceQualificationFixtureDirectoryBytes = 64

var errInvalidResourceQualificationFixture = errors.New("workerd resource qualification: invalid fixture directory")

func resourceQualificationArguments(directory string) ([]string, error) {
	if directory == string(filepath.Separator) || !filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory || strings.ContainsRune(directory, 0) ||
		len(directory) > maximumResourceQualificationFixtureDirectoryBytes {
		return nil, fmt.Errorf("%w: path must be short, canonical, and absolute", errInvalidResourceQualificationFixture)
	}
	return []string{
		"serve",
		"--experimental",
		"-I" + directory,
		filepath.Join(directory, "phase0-resource.capnp"),
	}, nil
}
