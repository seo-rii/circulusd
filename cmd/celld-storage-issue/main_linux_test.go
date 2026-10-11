//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/hancomac/circulusd/internal/conformance/celld/issuance"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestRunningProcessMeasurementRejectsPIDReuseAndChangedExecutable(t *testing.T) {
	dir := privateDirectory(t)
	path := filepath.Join(dir, "sleep")
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	put(t, path, data, 0700)
	command := exec.Command(path, "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	pid := uint32(command.Process.Pid)
	start, err := processStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	m := issuance.Measurement{ProcessID: pid, ProcessStartTimeTicks: start, BuildDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(data))}
	if err := verifyRunningProcess(m, uint64(len(data))); err != nil {
		t.Fatal(err)
	}
	m.ProcessStartTimeTicks++
	if err := verifyRunningProcess(m, uint64(len(data))); err == nil {
		t.Fatal("accepted reused PID/start identity")
	}
	m.ProcessStartTimeTicks = start
	m.BuildDigest = "sha256:" + strings.Repeat("0", 64)
	if err := verifyRunningProcess(m, uint64(len(data))); err == nil {
		t.Fatal("accepted different actual executable")
	}
}
func put(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateInputRejectsSymlinkDirectoryHardlinkAndBroadPermissions(t *testing.T) {
	dir := privateDirectory(t)
	good := filepath.Join(dir, "good")
	put(t, good, []byte("measured"), 0600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	broad := filepath.Join(dir, "broad")
	put(t, broad, []byte("private-material"), 0644)
	// File creation inherits the runner's umask; assert the intended unsafe
	// fixture permission explicitly even under the qualification's umask 077.
	if err := os.Chmod(broad, 0644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, broad, dir, "relative"} {
		if _, err := readPrivate(path, 64); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(good, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(good, 64); err == nil {
		t.Fatal("accepted multiply-linked authority input")
	}
}

func TestPrivateInputReadsAndHashesExactBoundedBytes(t *testing.T) {
	dir := privateDirectory(t)
	path := filepath.Join(dir, "binary")
	payload := []byte("actually selected raw executable bytes")
	put(t, path, payload, 0700)
	read, err := readPrivate(path, int64(len(payload)))
	if err != nil || !bytes.Equal(read, payload) {
		t.Fatalf("read=%q err=%v", read, err)
	}
	hash, size, err := hashPrivate(path, int64(len(payload)))
	expected := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
	if err != nil || hash != expected || size != uint64(len(payload)) {
		t.Fatalf("hash=%s size=%d err=%v", hash, size, err)
	}
	if _, err := readPrivate(path, int64(len(payload)-1)); err == nil {
		t.Fatal("accepted oversized input")
	}
}

func TestEvidenceRetentionIsExclusivePrivateAndPreservesForeignFiles(t *testing.T) {
	dir := privateDirectory(t)
	path := filepath.Join(dir, "evidence.json")
	payload := []byte("{\"signed\":true}\n")
	if err := retain(path, payload); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("stat=%v err=%v", st, err)
	}
	if err := retain(path, []byte("overwrite")); err == nil {
		t.Fatal("overwrote retained evidence")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatal("retained evidence changed")
	}
	foreign := filepath.Join(dir, "foreign")
	put(t, foreign, []byte("keep"), 0600)
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(foreign, symlink); err != nil {
		t.Fatal(err)
	}
	if err := retain(symlink, payload); err == nil {
		t.Fatal("followed evidence symlink")
	}
	if actual, _ := os.ReadFile(foreign); string(actual) != "keep" {
		t.Fatal("foreign file changed")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".native-evidence-") {
			t.Fatal("staging file leaked")
		}
	}
}

func TestEvidenceRetentionRequiresOwnedPrivateParent(t *testing.T) {
	dir := privateDirectory(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := retain(filepath.Join(dir, "evidence"), []byte("valid")); err == nil {
		t.Fatal("accepted broad parent")
	}
}

func TestIssuerConfigRejectsPASSClaimsAliasesAndDoesNotCreateEvidence(t *testing.T) {
	dir := privateDirectory(t)
	path := filepath.Join(dir, "config.json")
	out := filepath.Join(dir, "output.json")
	for _, content := range []string{`{"schemaVersion":1,"pass":true}`, `{"schemaVersion":1,"SchemaVersion":1}`, `{"schemaVersion":1,"schemaVersion":1}`, `{"schemaVersion":null}`} {
		put(t, path, []byte(content), 0600)
		var stdout, stderr bytes.Buffer
		if exit := run([]string{"--config", path, "--output", out}, &stdout, &stderr, time.Now); exit != 2 {
			t.Fatalf("exit=%d output=%s", exit, stderr.String())
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("failed issuance retained a file")
		}
		if stdout.Len() != 0 || strings.Contains(stderr.String(), "pass") || strings.Contains(stderr.String(), path) {
			t.Fatal("private config leaked in output")
		}
	}
}

func TestIssuerFailureOutputRedactsPrivateInput(t *testing.T) {
	dir := privateDirectory(t)
	path := filepath.Join(dir, "config.json")
	out := filepath.Join(dir, "output.json")
	c := issuerConfig{SchemaVersion: 1, SelectionFile: filepath.Join(dir, "secret-DO-NOT-PRINT"), LifetimeSeconds: 60}
	encoded, _ := json.Marshal(c)
	put(t, path, encoded, 0600)
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"--config", path, "--output", out}, &stdout, &stderr, time.Now); exit != 1 {
		t.Fatalf("exit=%d stderr=%s", exit, stderr.String())
	}
	if strings.Contains(stderr.String(), "DO-NOT-PRINT") || stdout.Len() != 0 {
		t.Fatal("private path escaped")
	}
}

func TestIssuerRequiresExplicitConfigAndOutput(t *testing.T) {
	for _, args := range [][]string{{}, {"--config", "/private/config"}, {"--output", "/private/evidence"}, {"--config", "/a", "--output", "/b", "unexpected"}} {
		var stdout, stderr bytes.Buffer
		if exit := run(args, &stdout, &stderr, time.Now); exit != 2 {
			t.Fatalf("exit=%d", exit)
		}
	}
}
