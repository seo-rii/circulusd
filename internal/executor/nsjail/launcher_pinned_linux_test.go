//go:build linux

package nsjail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type pinnedStarterFunc func(launchCommand) (launchedProcess, error)

func (f pinnedStarterFunc) Start(c launchCommand) (launchedProcess, error) { return f(c) }

func TestPinnedLauncherExecutesSealedELFAfterSourceReplacement(t *testing.T) {
	fixture := newLauncherFixture(t)
	source, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.plan.executable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.plan.executable, source, 0o500); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(source)
	fixture.plan.binaryDigest = "sha256:" + hex.EncodeToString(sum[:])
	fixture.plan.digest = digestLaunchPlan(fixture.plan)
	process := newFakeLaunchedProcess()
	var inherited []*os.File
	starter := pinnedStarterFunc(func(c launchCommand) (launchedProcess, error) {
		if c.Executable != "/proc/self/fd/4" || len(c.ExtraFiles) != 2 || len(c.Environment) != 0 {
			t.Fatalf("unexpected launch layout: %#v", c)
		}
		nonce, err := io.ReadAll(c.ExtraFiles[0])
		if err != nil || len(nonce) != 32 {
			t.Fatalf("nonce fd3: %d %v", len(nonce), err)
		}
		if err := os.Remove(fixture.plan.executable); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.plan.executable, []byte("replacement"), 0o500); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(c.ExtraFiles[1])
		if err != nil || !bytes.Equal(got, source) {
			t.Fatal("executed snapshot diverges from verified binary")
		}
		if _, err := c.ExtraFiles[1].WriteAt([]byte("x"), 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("snapshot mutable: %v", err)
		}
		seals, err := unix.FcntlInt(c.ExtraFiles[1].Fd(), unix.F_GET_SEALS, 0)
		wanted := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
		if err != nil || seals&wanted != wanted {
			t.Fatalf("snapshot seals = %d, %v", seals, err)
		}
		inherited = c.ExtraFiles
		return process, nil
	})
	instance, err := newLauncherWithNonceRegistry(starter, &recordingHandshakeNonceRegistry{}).Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range inherited {
		if _, err := fd.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("parent inherited descriptor leaked: %v", err)
		}
	}
	process.finish(nil)
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedLauncherRejectsMismatchScriptAndDigestTampering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   []byte
		digest string
		tamper bool
		want   error
	}{
		{"mismatch", []byte("binary"), "sha256:" + strings.Repeat("0", 64), false, ErrArtifactDigestMismatch},
		{"script", []byte("#!/bin/sh\nexit 0\n"), "", false, ErrUnsafeArtifact},
		{"seal", []byte("binary"), "", true, ErrPlanTampered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLauncherFixture(t)
			if err := os.Chmod(f.plan.executable, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.plan.executable, tc.body, 0o500); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(tc.body)
			f.plan.binaryDigest = "sha256:" + hex.EncodeToString(sum[:])
			if tc.digest != "" {
				f.plan.binaryDigest = tc.digest
			}
			f.plan.digest = digestLaunchPlan(f.plan)
			if tc.tamper {
				f.plan.binaryDigest = "sha256:" + strings.Repeat("f", 64)
			}
			starter := &recordingProcessStarter{process: newFakeLaunchedProcess()}
			_, err := newLauncherWithNonceRegistry(starter, &recordingHandshakeNonceRegistry{}).Start(context.Background(), f.plan)
			if !errors.Is(err, tc.want) || len(starter.snapshot()) != 0 {
				t.Fatalf("Start=%v, want %v before launch", err, tc.want)
			}
		})
	}
	for _, digest := range []string{"sha256:ABC", strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64)} {
		c := validConfig()
		c.BinaryDigest = digest
		if _, err := NewPlanner(c); err == nil {
			t.Fatalf("accepted invalid digest %q", digest)
		}
	}
}
