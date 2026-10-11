//go:build linux

package qualification

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/conformance/nsjail/fixture"
	"github.com/hancomac/circulusd/internal/release"
)

type signedFixture struct {
	config    qualificationConfig
	manifest  release.Manifest
	inventory environmentInventory
	rootfs    string
}

func signedQualificationFixture(t *testing.T, mutate ...func(*environmentInventory)) signedFixture {
	t.Helper()
	dir := t.TempDir()
	c := validTestConfig()
	c.ReleaseManifestPath = filepath.Join(dir, "release.json")
	c.TrustRootsPath = filepath.Join(dir, "roots.json")
	c.InstalledNsJailPath = filepath.Join(dir, "nsjail")
	c.EnvironmentInventoryPath = filepath.Join(dir, "inventory.json")
	c.EnvironmentRoot = filepath.Join(dir, "env")
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	sandboxd := []byte("sandboxd fixture bytes")
	helper := []byte("helper fixture bytes")
	seccomp := []byte("qualification policy fixture")
	binary := []byte("nsjail fixture bytes")
	commands := []byte(`{"schemaVersion":1,"commands":[{"name":"circulusd-nsjail-qualification","path":"/usr/bin/qualification-helper"}]}`)
	inv := environmentInventory{SchemaVersion: 1, Architecture: arch, SandboxdPath: "/usr/bin/sandboxd", SandboxdDigest: digestBytes(sandboxd), HelperPath: "/usr/bin/qualification-helper", HelperDigest: digestBytes(helper), SeccompDigest: digestBytes(seccomp), Entries: []inventoryEntry{}, Experiments: fixture.RequiredExperiments()}
	for _, d := range []string{"etc", "etc/circulusd", "usr", "usr/bin"} {
		inv.Entries = append(inv.Entries, inventoryEntry{Path: d, Kind: "directory", Mode: 0o700})
	}
	for path, raw := range map[string][]byte{"etc/circulusd/commands.json": commands, "usr/bin/sandboxd": sandboxd, "usr/bin/qualification-helper": helper} {
		mode := uint32(0o500)
		if strings.HasSuffix(path, ".json") {
			mode = 0o400
		}
		inv.Entries = append(inv.Entries, inventoryEntry{Path: path, Kind: "file", Mode: mode, Digest: digestBytes(raw)})
	}
	for _, change := range mutate {
		change(&inv)
	}
	inventoryRaw, _ := json.Marshal(inv)
	inventoryDigest := digestBytes(inventoryRaw)
	rootfs := filepath.Join(c.EnvironmentRoot, inventoryDigest, "nsjail/rootfs")
	for _, e := range inv.Entries {
		if e.Kind == "directory" {
			if err := os.MkdirAll(filepath.Join(rootfs, e.Path), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	for path, raw := range map[string][]byte{"etc/circulusd/commands.json": commands, "usr/bin/sandboxd": sandboxd, "usr/bin/qualification-helper": helper} {
		mode := os.FileMode(0o500)
		if strings.HasSuffix(path, ".json") {
			mode = 0o400
		}
		if err := os.WriteFile(filepath.Join(rootfs, path), raw, mode); err != nil {
			t.Fatal(err)
		}
	}
	policy := filepath.Join(c.EnvironmentRoot, inventoryDigest, "nsjail/seccomp", inv.SeccompDigest+".policy")
	if err := os.MkdirAll(filepath.Dir(policy), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{c.EnvironmentInventoryPath: inventoryRaw, policy: seccomp, c.InstalledNsJailPath: binary} {
		mode := os.FileMode(0o400)
		if path == c.InstalledNsJailPath {
			mode = 0o500
		}
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
	}
	m := release.Manifest{SchemaVersion: 1, Release: release.Release{Version: "1.0.0", Status: "candidate", Architectures: []string{arch}}, Toolchains: map[string]string{"go": "go1.25.0", "node": "24.0.0", "pnpm": "10.0.0", "protoc": "31.0", "protocGenGo": "1.36.0", "protocGenConnectGo": "1.18.0"}}
	for _, name := range []string{"platformd", "agentd", "executord", "sandboxd", "workerd", "celld", "session-host", "pi-runtime", "state-app", "nsjail", "nsjail-qualification-environment"} {
		raw := []byte(name)
		if name == "nsjail" {
			raw = binary
		}
		if name == "nsjail-qualification-environment" {
			raw = inventoryRaw
		}
		size := uint64(len(raw))
		a := release.Artifact{Architecture: arch, Name: name + ".bin", SHA256: digestBytes(raw)[7:], SizeBytes: &size}
		if name == "workerd" {
			a.ExtractionRecipe = release.ExtractionRecipeGzipSingleFileV1
			a.ExtractedExecutableSHA256 = a.SHA256
		}
		m.Components = append(m.Components, release.Component{Name: name, Version: "1.0.0", Commit: strings.Repeat("a", 40), License: "MIT", Source: "https://example.invalid/" + name, Qualification: "fixture-only", Artifacts: []release.Artifact{a}})
	}
	for _, pair := range []string{"platformd-agentd", "platformd-executord", "session-host-dynamic-worker", "executord-sandboxd", "state-app-schema"} {
		m.ProtocolCompatibility = append(m.ProtocolCompatibility, release.ProtocolCompatibility{Pair: pair, Minimum: release.ProtocolVersion{Major: 1}, Maximum: release.ProtocolVersion{Major: 1}, DescriptorSHA256: strings.Repeat("b", 64)})
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	for i := range m.Components {
		a := &m.Components[i].Artifacts[0]
		digest, err := release.ArtifactSigningDigest(m.Release, m.Components[i], *a)
		if err != nil {
			t.Fatal(err)
		}
		a.Signature = &release.Signature{Algorithm: "ed25519", KeyID: "fixture", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(digest)))}
	}
	digest, err := release.ManifestSigningDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signatures = []release.Signature{{Algorithm: "ed25519", KeyID: "fixture", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(digest)))}}
	manifestRaw, _ := json.Marshal(m)
	if err := os.WriteFile(c.ReleaseManifestPath, manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	roots := []byte(`{"schemaVersion":1,"roots":[{"keyId":"fixture","algorithm":"ed25519","publicKey":"` + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) + `"}]}`)
	if err := os.WriteFile(c.TrustRootsPath, roots, 0o600); err != nil {
		t.Fatal(err)
	}
	return signedFixture{c, m, inv, rootfs}
}

func TestSignedQualificationReleaseBindsExactEnvironmentInventory(t *testing.T) {
	f := signedQualificationFixture(t)
	resolved, err := resolveQualificationRelease(f.config)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.config.EnvironmentInventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.environmentDigest != digestBytes(raw) || resolved.rootfs != f.rootfs || resolved.binaryDigest != digestBytes([]byte("nsjail fixture bytes")) {
		t.Fatal("resolved identity was caller-supplied or incomplete")
	}
}

func TestSignedQualificationReleaseRejectsUnsafeOrSubstitutedInputs(t *testing.T) {
	for _, name := range []string{"unsigned", "development", "untrusted root", "inventory substitution", "extra file", "missing file", "helper changed", "policy changed", "binary changed", "symlink", "metadata writable", "signed binary size mismatch", "signed inventory size mismatch"} {
		t.Run(name, func(t *testing.T) {
			f := signedQualificationFixture(t)
			overwrite := func(path string, b []byte) {
				t.Helper()
				if err := os.Chmod(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0o500); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "unsigned":
				f.manifest.Signatures = nil
				raw, _ := json.Marshal(f.manifest)
				overwrite(f.config.ReleaseManifestPath, raw)
			case "development":
				f.manifest.Release.Status = "development"
				raw, _ := json.Marshal(f.manifest)
				overwrite(f.config.ReleaseManifestPath, raw)
			case "untrusted root":
				overwrite(f.config.TrustRootsPath, []byte(`{"schemaVersion":1,"roots":[{"keyId":"other","algorithm":"ed25519","publicKey":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"}]}`))
			case "inventory substitution":
				overwrite(f.config.EnvironmentInventoryPath, []byte(`{}`))
			case "extra file":
				if err := os.WriteFile(filepath.Join(f.rootfs, "extra"), []byte("extra"), 0o400); err != nil {
					t.Fatal(err)
				}
			case "missing file":
				if err := os.Remove(filepath.Join(f.rootfs, "usr/bin/qualification-helper")); err != nil {
					t.Fatal(err)
				}
			case "helper changed":
				overwrite(filepath.Join(f.rootfs, "usr/bin/qualification-helper"), []byte("substitute"))
			case "policy changed":
				overwrite(filepath.Join(filepath.Dir(f.rootfs), "seccomp", f.inventory.SeccompDigest+".policy"), []byte("ALLOW ALL"))
			case "binary changed":
				overwrite(f.config.InstalledNsJailPath, []byte("substitute"))
			case "symlink":
				original := f.config.TrustRootsPath
				f.config.TrustRootsPath = filepath.Join(filepath.Dir(original), "alias")
				if err := os.Symlink(original, f.config.TrustRootsPath); err != nil {
					t.Fatal(err)
				}

			case "signed binary size mismatch", "signed inventory size mismatch":
				componentName := "nsjail"
				if name == "signed inventory size mismatch" {
					componentName = "nsjail-qualification-environment"
				}
				key := ed25519.NewKeyFromSeed(make([]byte, 32))
				for i := range f.manifest.Components {
					component := &f.manifest.Components[i]
					if component.Name != componentName {
						continue
					}
					size := uint64(1)
					component.Artifacts[0].SizeBytes = &size
					digest, err := release.ArtifactSigningDigest(f.manifest.Release, *component, component.Artifacts[0])
					if err != nil {
						t.Fatal(err)
					}
					component.Artifacts[0].Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(digest)))
				}
				digest, err := release.ManifestSigningDigest(f.manifest)
				if err != nil {
					t.Fatal(err)
				}
				f.manifest.Signatures[0].Value = base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(digest)))
				raw, _ := json.Marshal(f.manifest)
				overwrite(f.config.ReleaseManifestPath, raw)
			case "metadata writable":
				if err := os.Chmod(f.config.ReleaseManifestPath, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := resolveQualificationRelease(f.config); err == nil {
				t.Fatal("unsafe release accepted")
			}
		})
	}
}

func TestSignedEnvironmentCannotChangeOrOmitBoundedExperiments(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*environmentInventory)
	}{
		{"missing", func(i *environmentInventory) { i.Experiments = fixture.ExperimentDescriptor{} }},
		{"syscall", func(i *environmentInventory) { i.Experiments.SeccompSyscall = "getpid" }},
		{"errno", func(i *environmentInventory) { i.Experiments.SeccompErrno = 0 }},
		{"CPU", func(i *environmentInventory) { i.Experiments.CPUMillis++ }},
		{"memory", func(i *environmentInventory) { i.Experiments.MemoryBytes++ }},
		{"PIDs", func(i *environmentInventory) { i.Experiments.PIDsAttempts++ }},
		{"address space", func(i *environmentInventory) { i.Experiments.AddressSpaceBytes++ }},
		{"nproc", func(i *environmentInventory) { i.Experiments.MaximumUserProcesses++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := signedQualificationFixture(t, tc.mutate)
			if _, err := resolveQualificationRelease(f.config); err == nil {
				t.Fatal("unsupported signed experiment descriptor accepted")
			}
		})
	}
}
