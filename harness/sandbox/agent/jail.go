//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// runJailInit is the unshare launcher's init: it runs as root inside the user
// namespace (`unshare --user --map-users=<uid>,0,1 --map-users=<subuid>,1000,1
// --mount --pid --net ...`), builds a private tmpfs root from read-only bind
// mounts, seals the command manifest, pivots into the new root, and execs
// sandboxd. The mount(2) syscall is used directly because the util-linux
// mount binary refuses non-root callers even with capabilities in a user
// namespace. Nothing here is a security boundary of its own: the namespaces
// are.
func runJailInit(args []string) int {
	flags := flag.NewFlagSet("jail-init", flag.ContinueOnError)
	root := flags.String("root", "", "mount point for the new tmpfs root")
	control := flags.String("control", "", "host directory bound to /run/circulusd/control")
	sandboxd := flags.String("sandboxd", "", "host path of the sandboxd binary")
	python := flags.String("python", "/usr/bin/python3", "interpreter path")
	manifest := flags.String("manifest", "", "command manifest JSON")
	workspaceSize := flags.String("workspace-size", defaultWorkspaceSize, "tmpfs size of /workspace")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	command := flags.Args()
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if *root == "" || *control == "" || *sandboxd == "" || *manifest == "" || len(command) == 0 {
		fmt.Fprintln(os.Stderr, "jail-init: --root, --control, --sandboxd, --manifest, and a command are required")
		return 2
	}
	if err := jailInit(*root, *control, *sandboxd, *python, *manifest, *workspaceSize, command); err != nil {
		fmt.Fprintf(os.Stderr, "jail-init: %v\n", err)
		return 1
	}
	return 0
}

func mount(source, target, fstype string, flags uintptr, data string) error {
	if err := unix.Mount(source, target, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %q -> %q: %w", source, target, err)
	}
	return nil
}

func bindMount(source, target string, readonly, noexec bool) error {
	if err := mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_NOSUID | unix.MS_NODEV)
	if readonly {
		flags |= unix.MS_RDONLY
	}
	if noexec {
		flags |= unix.MS_NOEXEC
	}
	return mount("", target, "", flags, "")
}

func writeOwned(path, content string, mode os.FileMode, owner int) error {
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if owner >= 0 {
		return os.Chown(path, owner, owner)
	}
	return nil
}

func jailInit(root, control, sandboxd, python, manifestJSON, workspaceSize string, command []string) error {
	if os.Getuid() != 0 {
		return fmt.Errorf("must run as root inside the user namespace (uid %d)", os.Getuid())
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(manifestJSON), &manifest); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	if err := mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return err
	}
	if err := os.Chdir(root); err != nil {
		return err
	}
	for _, directory := range []string{"usr", "etc/circulusd", "dev", "proc", "tmp", "workspace", "run/circulusd/control", "sandbox", "oldroot"} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	if err := bindMount("/usr", "usr", true, false); err != nil {
		return err
	}
	for _, link := range []string{"bin", "lib", "sbin", "lib64", "lib32"} {
		if _, err := os.Stat("/" + link); err == nil {
			if err := os.Symlink("usr/"+link, link); err != nil {
				return err
			}
		}
	}
	for _, name := range []string{"ld.so.cache", "localtime"} {
		if content, err := os.ReadFile("/etc/" + name); err == nil {
			_ = os.WriteFile("etc/"+name, content, 0o644)
		}
	}
	files := map[string]string{
		"etc/passwd":   fmt.Sprintf("root:x:0:0::/:/usr/bin/false\nsandbox:x:%d:%d::/workspace:/usr/bin/false\n", unprivilegedUID, unprivilegedUID),
		"etc/group":    fmt.Sprintf("root:x:0:\nsandbox:x:%d:\n", unprivilegedUID),
		"etc/hostname": "sandbox\n",
		"etc/hosts":    "127.0.0.1 localhost sandbox\n",
	}
	for path, content := range files {
		if err := writeOwned(path, content, 0o644, -1); err != nil {
			return err
		}
	}
	// Sealed command manifest: regular file, one link, owned by the
	// unprivileged inner uid (sandboxd rejects a root-owned manifest), not
	// group/world writable, and bind-mounted read-only.
	sealed, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := writeOwned("etc/circulusd/commands.json", string(sealed)+"\n", 0o644, unprivilegedUID); err != nil {
		return err
	}
	if err := bindMount("etc/circulusd/commands.json", "etc/circulusd/commands.json", true, true); err != nil {
		return err
	}
	// Python wrapper: sandboxd runs manifest commands as inner root with an
	// empty environment; the wrapper drops to the unprivileged inner uid.
	if err := writeOwned("sandbox/python3", pythonWrapperScript(python, true), 0o755, -1); err != nil {
		return err
	}
	if err := os.WriteFile("sandbox/sandboxd", nil, 0o755); err != nil {
		return err
	}
	if err := bindMount(sandboxd, "sandbox/sandboxd", true, false); err != nil {
		return err
	}
	if err := mount("tmpfs", "dev", "tmpfs", unix.MS_NOSUID, "mode=0755"); err != nil {
		return err
	}
	for _, node := range []string{"null", "zero", "random", "urandom"} {
		if err := os.WriteFile("dev/"+node, nil, 0o666); err != nil {
			return err
		}
		if err := mount("/dev/"+node, "dev/"+node, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	if err := mount("proc", "proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	// Sized like the docker launcher's /tmp; an unsized tmpfs may grow to half the host's RAM.
	if err := mount("tmpfs", "tmp", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=64m"); err != nil {
		return err
	}
	if err := mount("tmpfs", "workspace", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size="+workspaceSize); err != nil {
		return err
	}
	if err := os.Chown("workspace", unprivilegedUID, unprivilegedUID); err != nil {
		return err
	}
	if err := bindMount(control, "run/circulusd/control", false, true); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "oldroot"); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/oldroot", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount old root: %w", err)
	}
	if err := os.Remove("/oldroot"); err != nil {
		return err
	}
	return unix.Exec(command[0], command, []string{})
}

// runWriteManifest runs inside a throwaway user namespace whose inner uid
// 1000 is mapped to the subordinate uid: it writes the manifest and chowns it
// so nsjail (with the same mapping) sees a file owned by the unprivileged uid.
func runWriteManifest(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "write-manifest: <path> <json>")
		return 2
	}
	path, document := args[0], args[1]
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeOwned(path, document+"\n", 0o644, unprivilegedUID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
