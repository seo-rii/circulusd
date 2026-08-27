//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hancomac/circulusd/internal/sandboxd"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
	"golang.org/x/sys/unix"
)

const testSandboxID = "sandbox_AAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestExecuteServesLaunchAuthorityAndFencesOnExit(t *testing.T) {
	t.Parallel()

	nonce := bytes.Repeat([]byte{0x5a}, launchNonceBytes)
	runner := sandboxd.NewFakeRunner()
	server := &recordingServer{}
	var supervisor *sandboxd.Supervisor
	var supervisorConfig sandboxd.Config
	var transportConfig sandboxrpc.ServerConfig
	var observedNonce []byte
	dependencies := daemonDependencies{
		stderr: io.Discard,
		readNonce: func() ([]byte, error) {
			return append([]byte(nil), nonce...), nil
		},
		loadCommands: func(path string) (map[string]string, error) {
			if path != "/etc/circulusd/commands.json" {
				t.Fatalf("command manifest path = %q", path)
			}
			return map[string]string{"echo": "/usr/bin/echo"}, nil
		},
		newSupervisor: func(config sandboxd.Config) (*sandboxd.Supervisor, error) {
			supervisorConfig = config
			created, err := sandboxd.NewSupervisor(config)
			supervisor = created
			return created, err
		},
		listen: func(config sandboxrpc.ServerConfig) (daemonServer, error) {
			transportConfig = config
			observedNonce = append([]byte(nil), config.OneTimeNonce...)
			return server, nil
		},
		runner: runner,
	}

	exitCode := execute(context.Background(), []string{
		"--control-socket", "/run/circulusd/control/control.sock",
		"--sandbox-id", testSandboxID,
		"--generation", "7",
		"--protocol-version", "1",
		"--allow-client-uid", "65534",
	}, dependencies)
	if exitCode != 0 {
		t.Fatalf("execute() = %d, want 0", exitCode)
	}
	if supervisorConfig.Authority != (sandboxd.LaunchAuthority{SandboxID: testSandboxID, Generation: 7}) {
		t.Fatalf("supervisor authority = %#v", supervisorConfig.Authority)
	}
	if supervisorConfig.WorkspaceRoot != "/workspace" || supervisorConfig.Runner != runner ||
		supervisorConfig.Commands["echo"] != "/usr/bin/echo" {
		t.Fatalf("supervisor config = %#v", supervisorConfig)
	}
	if transportConfig.SocketPath != "/run/circulusd/control/control.sock" ||
		transportConfig.SandboxGeneration != 7 || string(transportConfig.SandboxID) != testSandboxID ||
		len(transportConfig.AllowedClientUIDs) != 1 || transportConfig.AllowedClientUIDs[0] != 65534 ||
		transportConfig.Supervisor != supervisor {
		t.Fatalf("transport config = %#v", transportConfig)
	}
	if !bytes.Equal(observedNonce, nonce) {
		t.Fatalf("listen nonce = %x", observedNonce)
	}
	if !allZero(transportConfig.OneTimeNonce) {
		t.Fatal("execute retained the launch nonce after listener construction")
	}
	if server.serves != 1 || server.closes != 1 {
		t.Fatalf("server lifecycle = serves:%d closes:%d", server.serves, server.closes)
	}
	if authority := supervisor.LaunchAuthority(); authority.Generation != 8 {
		t.Fatalf("shutdown fence generation = %d, want 8", authority.Generation)
	}
}

func TestExecuteRejectsInvalidLaunchArgumentsBeforeReadingAuthority(t *testing.T) {
	t.Parallel()

	valid := []string{
		"--control-socket", "/run/circulusd/control/control.sock",
		"--sandbox-id", testSandboxID,
		"--generation", "7",
		"--protocol-version", "1",
		"--allow-client-uid", "65534",
	}
	withoutFlag := func(name string) []string {
		result := make([]string, 0, len(valid)-2)
		for index := 0; index < len(valid); index += 2 {
			if valid[index] != name {
				result = append(result, valid[index], valid[index+1])
			}
		}
		return result
	}
	replaceFlag := func(name, value string) []string {
		result := append([]string(nil), valid...)
		for index := 0; index < len(result); index += 2 {
			if result[index] == name {
				result[index+1] = value
				return result
			}
		}
		t.Fatalf("test flag %q not found", name)
		return nil
	}
	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "missing sandbox ID", arguments: withoutFlag("--sandbox-id")},
		{name: "invalid sandbox ID", arguments: replaceFlag("--sandbox-id", "sandbox-alpha")},
		{name: "zero generation", arguments: replaceFlag("--generation", "0")},
		{name: "noncanonical generation", arguments: replaceFlag("--generation", "07")},
		{name: "unsupported protocol", arguments: replaceFlag("--protocol-version", "2")},
		{name: "no allowed client", arguments: withoutFlag("--allow-client-uid")},
		{name: "noncanonical UID", arguments: replaceFlag("--allow-client-uid", "065534")},
		{name: "relative socket", arguments: replaceFlag("--control-socket", "control.sock")},
		{name: "duplicate UID", arguments: append(append([]string(nil), valid...), "--allow-client-uid", "65534")},
		{name: "duplicate socket", arguments: append(append([]string(nil), valid...), "--control-socket", "/tmp/other.sock")},
		{name: "extra argument", arguments: append(append([]string(nil), valid...), "extra")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			read := false
			exitCode := execute(context.Background(), test.arguments, daemonDependencies{
				stderr: io.Discard,
				readNonce: func() ([]byte, error) {
					read = true
					return nil, errors.New("must not be called")
				},
				loadCommands: func(string) (map[string]string, error) {
					t.Fatal("invalid arguments reached command manifest loading")
					return nil, nil
				},
			})
			if exitCode != 2 || read {
				t.Fatalf("execute() = %d, nonce read = %t", exitCode, read)
			}
		})
	}
}

func TestExecuteFailsClosedAndClearsNonceOnStartupErrors(t *testing.T) {
	t.Parallel()

	arguments := []string{
		"--control-socket", "/run/circulusd/control/control.sock",
		"--sandbox-id", testSandboxID,
		"--generation", "7",
		"--protocol-version", "1",
		"--allow-client-uid", "65534",
	}
	t.Run("pre-canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		read := false
		exitCode := execute(ctx, arguments, daemonDependencies{
			stderr: io.Discard,
			loadCommands: func(string) (map[string]string, error) {
				t.Fatal("pre-canceled daemon loaded the command manifest")
				return nil, nil
			},
			readNonce: func() ([]byte, error) {
				read = true
				return nil, nil
			},
			newSupervisor: sandboxd.NewSupervisor,
			listen: func(sandboxrpc.ServerConfig) (daemonServer, error) {
				return nil, errors.New("must not listen")
			},
			runner: sandboxd.NewFakeRunner(),
		})
		if exitCode != 1 || read {
			t.Fatalf("execute(pre-canceled) = %d, nonce read = %t", exitCode, read)
		}
	})
	t.Run("nonce read", func(t *testing.T) {
		t.Parallel()
		exitCode := execute(context.Background(), arguments, daemonDependencies{
			stderr: io.Discard,
			loadCommands: func(string) (map[string]string, error) {
				return map[string]string{"echo": "/usr/bin/echo"}, nil
			},
			readNonce: func() ([]byte, error) { return nil, errors.New("read failed") },
		})
		if exitCode != 1 {
			t.Fatalf("execute() = %d, want 1", exitCode)
		}
	})

	t.Run("listen", func(t *testing.T) {
		t.Parallel()
		nonce := bytes.Repeat([]byte{0xa5}, launchNonceBytes)
		var passedNonce []byte
		exitCode := execute(context.Background(), arguments, daemonDependencies{
			stderr: io.Discard,
			loadCommands: func(string) (map[string]string, error) {
				return map[string]string{"echo": "/usr/bin/echo"}, nil
			},
			readNonce:     func() ([]byte, error) { return nonce, nil },
			newSupervisor: sandboxd.NewSupervisor,
			listen: func(config sandboxrpc.ServerConfig) (daemonServer, error) {
				passedNonce = config.OneTimeNonce
				return nil, errors.New("listen failed")
			},
			runner: sandboxd.NewFakeRunner(),
		})
		if exitCode != 1 || !allZero(nonce) || !allZero(passedNonce) {
			t.Fatalf("execute() = %d, nonce = %x, passed = %x", exitCode, nonce, passedNonce)
		}
	})
}

func TestExecuteFailsClosedOnIncompleteDependencyAdapters(t *testing.T) {
	t.Parallel()

	if exitCode := execute(context.Background(), []string{"--unknown"}, daemonDependencies{}); exitCode != 2 {
		t.Fatalf("execute(unknown flag, nil stderr) = %d, want 2", exitCode)
	}
	arguments := []string{
		"--control-socket", "/run/circulusd/control/control.sock",
		"--sandbox-id", testSandboxID,
		"--generation", "7",
		"--protocol-version", "1",
		"--allow-client-uid", "65534",
	}
	base := daemonDependencies{
		stderr: io.Discard,
		loadCommands: func(string) (map[string]string, error) {
			return map[string]string{"echo": "/usr/bin/echo"}, nil
		},
		readNonce: func() ([]byte, error) {
			return bytes.Repeat([]byte{0x5a}, launchNonceBytes), nil
		},
		runner: sandboxd.NewFakeRunner(),
	}
	t.Run("nil supervisor", func(t *testing.T) {
		dependencies := base
		dependencies.newSupervisor = func(sandboxd.Config) (*sandboxd.Supervisor, error) {
			return nil, nil
		}
		dependencies.listen = func(sandboxrpc.ServerConfig) (daemonServer, error) {
			t.Fatal("nil supervisor reached listener construction")
			return nil, nil
		}
		if exitCode := execute(context.Background(), arguments, dependencies); exitCode != 1 {
			t.Fatalf("execute(nil supervisor) = %d, want 1", exitCode)
		}
	})
	t.Run("nil server", func(t *testing.T) {
		dependencies := base
		dependencies.newSupervisor = sandboxd.NewSupervisor
		dependencies.listen = func(sandboxrpc.ServerConfig) (daemonServer, error) {
			return nil, nil
		}
		if exitCode := execute(context.Background(), arguments, dependencies); exitCode != 1 {
			t.Fatalf("execute(nil server) = %d, want 1", exitCode)
		}
	})
}

func TestReadLaunchNonceFDRequiresExactAnonymousPipe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		wantErr bool
	}{
		{name: "exact", payload: bytes.Repeat([]byte{0x5a}, launchNonceBytes)},
		{name: "short", payload: bytes.Repeat([]byte{0x5a}, launchNonceBytes-1), wantErr: true},
		{name: "trailing byte", payload: bytes.Repeat([]byte{0x5a}, launchNonceBytes+1), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			duplicate, err := unix.Dup(int(read.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			if err := read.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := write.Write(test.payload); err != nil {
				t.Fatal(err)
			}
			if err := write.Close(); err != nil {
				t.Fatal(err)
			}
			nonce, err := readLaunchNonceFD(duplicate)
			if test.wantErr {
				if err == nil || nonce != nil {
					t.Fatalf("readLaunchNonceFD() = %x, %v", nonce, err)
				}
				return
			}
			if err != nil || !bytes.Equal(nonce, test.payload) {
				t.Fatalf("readLaunchNonceFD() = %x, %v", nonce, err)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "nonce")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x5a}, launchNonceBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	duplicate, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if nonce, err := readLaunchNonceFD(duplicate); err == nil || nonce != nil {
		t.Fatalf("readLaunchNonceFD(regular) = %x, %v", nonce, err)
	}
}

type recordingServer struct {
	serves int
	closes int
}

func (server *recordingServer) Serve(context.Context) error {
	server.serves++
	return nil
}

func (server *recordingServer) Close() error {
	server.closes++
	return nil
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
