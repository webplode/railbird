//go:build unix

// Package privilege enforces the process identity used by the ingress runtime.
package privilege

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
)

var (
	// ErrUnsafeOwnership indicates that the bootstrap mount root has an
	// ownership presentation other than root:root or the requested identity.
	ErrUnsafeOwnership = errors.New("unsafe bootstrap mount-root ownership")
	// ErrIdentityMismatch indicates that the process credentials do not exactly
	// match the requested runtime identity.
	ErrIdentityMismatch = errors.New("runtime identity mismatch")
	// ErrRootRegained indicates that a supposedly irreversible privilege drop
	// allowed the process to become root again.
	ErrRootRegained = errors.New("root privileges could be regained")
)

type mountRoot struct {
	uid int
	gid int
	dir bool
	dev uint64
	ino uint64
}

type operations struct {
	openRoot  func(string) (int, error)
	fstat     func(int) (mountRoot, error)
	fchown    func(int, int, int) error
	close     func(int) error
	setgroups func([]int) error
	setgid    func(int) error
	setuid    func(int) error
	getuid    func() int
	geteuid   func() int
	getgid    func() int
	getegid   func() int
	getgroups func() ([]int, error)
	fatal     func(error)
}

var systemOperations = operations{
	openRoot: func(path string) (int, error) {
		return syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	},
	fstat: func(fd int) (mountRoot, error) {
		var stat syscall.Stat_t
		if err := syscall.Fstat(fd, &stat); err != nil {
			return mountRoot{}, err
		}
		return mountRoot{
			uid: int(stat.Uid),
			gid: int(stat.Gid),
			dir: uint32(stat.Mode)&syscall.S_IFMT == syscall.S_IFDIR,
			dev: uint64(stat.Dev),
			ino: uint64(stat.Ino),
		}, nil
	},
	fchown:    syscall.Fchown,
	close:     syscall.Close,
	setgroups: syscall.Setgroups,
	setgid:    syscall.Setgid,
	setuid:    syscall.Setuid,
	getuid:    os.Getuid,
	geteuid:   os.Geteuid,
	getgid:    os.Getgid,
	getegid:   os.Getegid,
	getgroups: os.Getgroups,
	fatal: func(err error) {
		log.Printf("fatal privilege-boundary failure: %v", err)
		os.Exit(1)
	},
}

// PrepareBootstrap classifies the ingress bootstrap before making any
// mutation, validates and (when necessary) transfers ownership of only the
// mount-root inode, then irreversibly drops to uid:gid.
func PrepareBootstrap(root string, uid, gid int, classify func() error) error {
	return prepareBootstrap(root, uid, gid, classify, systemOperations)
}

// RequireRuntimeIdentity refuses to serve unless the process has exactly the
// requested real/effective uid and gid and no supplementary group identities
// beyond a runtime-provided duplicate of the requested primary gid.
func RequireRuntimeIdentity(uid, gid int) error {
	return requireRuntimeIdentity(uid, gid, systemOperations)
}

func prepareBootstrap(root string, uid, gid int, classify func() error, ops operations) (resultErr error) {
	if root == "" {
		return errors.New("bootstrap mount root is empty")
	}
	if uid <= 0 || gid <= 0 {
		return fmt.Errorf("runtime uid and gid must be non-root: uid=%d gid=%d", uid, gid)
	}
	if classify == nil {
		return errors.New("bootstrap classifier is nil")
	}
	if err := requireInitialRootIdentity(ops); err != nil {
		return err
	}

	fd, err := ops.openRoot(root)
	if err != nil {
		return fmt.Errorf("open bootstrap mount root without following symlinks: %w", err)
	}
	defer func() {
		if err := ops.close(fd); err != nil {
			closeErr := fmt.Errorf("close bootstrap mount-root descriptor: %w", err)
			if resultErr == nil {
				resultErr = closeErr
			} else {
				resultErr = errors.Join(resultErr, closeErr)
			}
		}
	}()

	before, err := ops.fstat(fd)
	if err != nil {
		return fmt.Errorf("fstat bootstrap mount root before classification: %w", err)
	}
	if !before.dir {
		return fmt.Errorf("%w: mount root must be a directory", ErrUnsafeOwnership)
	}

	// Classification deliberately precedes every possible mutation.
	if err := classify(); err != nil {
		return fmt.Errorf("classify bootstrap: %w", err)
	}

	after, err := ops.fstat(fd)
	if err != nil {
		return fmt.Errorf("fstat bootstrap mount root after classification: %w", err)
	}
	if before != after {
		return fmt.Errorf("%w: mount-root descriptor changed during classification (before=%s after=%s)", ErrUnsafeOwnership, formatMountRoot(before), formatMountRoot(after))
	}

	switch {
	case after.uid == 0 && after.gid == 0:
		if err := ops.fchown(fd, uid, gid); err != nil {
			return fmt.Errorf("transfer bootstrap mount-root ownership: %w", err)
		}
	case after.uid == uid && after.gid == gid:
		// The volume may retain ownership from a previous bootstrap.
	default:
		return fmt.Errorf("%w: got %d:%d, require 0:0 or %d:%d", ErrUnsafeOwnership, after.uid, after.gid, uid, gid)
	}

	verified, err := ops.fstat(fd)
	if err != nil {
		return fmt.Errorf("fstat bootstrap mount root after ownership validation: %w", err)
	}
	if verified.dev != after.dev || verified.ino != after.ino || !verified.dir || verified.uid != uid || verified.gid != gid {
		return fmt.Errorf("%w: mount-root descriptor changed or ownership was not applied (before=%s after=%s)", ErrUnsafeOwnership, formatMountRoot(after), formatMountRoot(verified))
	}

	if err := dropIdentity(uid, gid, ops); err != nil {
		return err
	}
	if err := requireRuntimeIdentity(uid, gid, ops); err != nil {
		return fmt.Errorf("verify dropped identity: %w", err)
	}

	if err := ops.setuid(0); err != nil {
		return nil
	}

	// A successful regain invalidates the security boundary. Re-drop before
	// returning so a caller cannot accidentally continue as root. If recovery
	// cannot be proven, terminate rather than returning control in an unsafe
	// identity. Tests inject fatal so this path is deterministic and harmless.
	regainErr := ErrRootRegained
	if err := recoverAfterRootRegain(uid, gid, ops); err != nil {
		fatalErr := fmt.Errorf("%w; recovery failed: %v", regainErr, err)
		ops.fatal(fatalErr)
		return fatalErr
	}
	return regainErr
}

func requireInitialRootIdentity(ops operations) error {
	if uid, euid, gid, egid := ops.getuid(), ops.geteuid(), ops.getgid(), ops.getegid(); uid != 0 || euid != 0 || gid != 0 || egid != 0 {
		return fmt.Errorf("initial process identity must be root: uid=%d euid=%d gid=%d egid=%d", uid, euid, gid, egid)
	}
	return nil
}

func formatMountRoot(root mountRoot) string {
	return fmt.Sprintf("dev=%d ino=%d owner=%d:%d dir=%t", root.dev, root.ino, root.uid, root.gid, root.dir)
}

func dropIdentity(uid, gid int, ops operations) error {
	if err := ops.setgroups([]int{}); err != nil {
		return fmt.Errorf("clear supplementary groups: %w", err)
	}
	if err := ops.setgid(gid); err != nil {
		return fmt.Errorf("set runtime gid %d: %w", gid, err)
	}
	if err := ops.setuid(uid); err != nil {
		return fmt.Errorf("set runtime uid %d: %w", uid, err)
	}
	return nil
}

func recoverAfterRootRegain(uid, gid int, ops operations) error {
	if err := dropIdentity(uid, gid, ops); err != nil {
		return err
	}
	if err := requireRuntimeIdentity(uid, gid, ops); err != nil {
		return fmt.Errorf("verify recovered identity: %w", err)
	}
	return nil
}

func requireRuntimeIdentity(uid, gid int, ops operations) error {
	groups, err := ops.getgroups()
	if err != nil {
		return fmt.Errorf("read supplementary groups: %w", err)
	}
	if gotUID, gotEUID, gotGID, gotEGID := ops.getuid(), ops.geteuid(), ops.getgid(), ops.getegid(); gotUID != uid || gotEUID != uid || gotGID != gid || gotEGID != gid {
		return fmt.Errorf("%w: uid=%d euid=%d gid=%d egid=%d, require %d:%d", ErrIdentityMismatch, gotUID, gotEUID, gotGID, gotEGID, uid, gid)
	}
	for _, group := range groups {
		if group != gid {
			return fmt.Errorf("%w: supplementary groups=%v, allow none or primary gid %d only", ErrIdentityMismatch, groups, gid)
		}
	}
	return nil
}
