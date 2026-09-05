//go:build linux

package materialized_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzSymlinkScanMaterialize generates bounded real directory/link graphs and
// compares kernel resolution before and after Scan/Materialize. The safe branch
// must succeed; arbitrary graphs may be rejected but cannot escape or retarget.
func FuzzSymlinkScanMaterialize(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3}, []byte{1}, []byte("payload"))
	f.Add([]byte{0, 0, 0, 0, 0}, []byte{6, 4, 5, 2}, []byte{0, 0xff})
	f.Add([]byte{1, 2, 3}, []byte{0, 7, 4}, []byte{})
	f.Add([]byte{1, 0, 1, 0}, []byte{9, 7, 4}, []byte("escape"))
	f.Fuzz(func(t *testing.T, topology, components, payload []byte) {
		if len(topology) == 0 {
			topology = []byte{0}
		}
		if len(components) == 0 {
			components = []byte{0}
		}
		if len(payload) > 64 {
			payload = payload[:64]
		}
		count := 1 + len(topology)%6
		mustAccept := topology[0]&1 == 0
		files := make(map[string][]byte)
		for _, name := range []string{"file", "dir/file", "dir/nested/file", "other/file", "other/deep/file"} {
			files[name] = append([]byte(name+":"), payload...)
		}
		names := make([]string, count)
		for index := range names {
			names[index] = fmt.Sprintf("link%d", index)
			if topology[index%len(topology)]&2 != 0 {
				names[index] = "dir/" + names[index]
			}
		}
		links := make(map[string]string, count)
		for index, name := range names {
			var target string
			if mustAccept {
				destination := "dir/nested"
				if index > 0 {
					destination = names[index-1]
				}
				var err error
				target, err = filepath.Rel(filepath.Dir(name), destination)
				if err != nil {
					t.Fatal(err)
				}
				if index > 0 {
					suffixes := []string{"", "/../file", "/./", "//file", "/", "/../missing", "/missing/../file"}
					target += suffixes[int(components[index%len(components)])%len(suffixes)]
				}
			} else {
				words := []string{"dir", "nested", "other", "deep", "file", "missing", ".", "..", "", "link0", "link1", "link2"}
				parts := make([]string, 1+int(topology[index%len(topology)])%8)
				for position := range parts {
					parts[position] = words[int(components[(index+position)%len(components)])%len(words)]
				}
				target = strings.Join(parts, "/")
				if target == "" {
					target = "."
				}
			}
			links[name] = target
		}
		checkSymlinkRoundTrip(t, []string{"dir/nested", "other/deep"}, files, links, mustAccept)
	})
}
