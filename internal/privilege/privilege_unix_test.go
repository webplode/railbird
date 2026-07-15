//go:build unix

package privilege

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

const (
	testUID = 65532
	testGID = 65532
	testFD  = 41
)

type fakeSystem struct {
	root         mountRoot
	uid          int
	euid         int
	gid          int
	egID         int
	groups       []int
	events       []string
	fail         map[string]error
	fstatResults map[int]mountRoot
	fstatCalls   int
	fchownFDs    []int
	closeCalls   int
	allowRegain  bool
	fatalErr     error
}

func newFakeSystem(ownerUID, ownerGID int) *fakeSystem {
	return &fakeSystem{
		root:         mountRoot{uid: ownerUID, gid: ownerGID, dir: true, dev: 7, ino: 11},
		groups:       []int{0, 20},
		fail:         make(map[string]error),
		fstatResults: make(map[int]mountRoot),
	}
}

func TestSystemOpenRootDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "mount-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if fd, err := systemOperations.openRoot(link); err == nil {
		_ = systemOperations.close(fd)
		t.Fatal("openRoot() followed a symlink")
	}

	fd, err := systemOperations.openRoot(dir)
	if err != nil {
		t.Fatalf("openRoot(directory) error = %v", err)
	}
	root, err := systemOperations.fstat(fd)
	if err != nil {
		_ = systemOperations.close(fd)
		t.Fatalf("fstat(directory) error = %v", err)
	}
	if !root.dir || root.dev == 0 || root.ino == 0 {
		_ = systemOperations.close(fd)
		t.Fatalf("fstat(directory) = %+v, want directory identity", root)
	}
	if err := systemOperations.close(fd); err != nil {
		t.Fatalf("close(directory) error = %v", err)
	}
}

func (f *fakeSystem) ops() operations {
	return operations{
		openRoot: func(path string) (int, error) {
			f.events = append(f.events, "open:"+path)
			if err := f.fail["open"]; err != nil {
				return -1, err
			}
			return testFD, nil
		},
		fstat: func(fd int) (mountRoot, error) {
			f.fstatCalls++
			key := "fstat:" + string(rune('0'+f.fstatCalls))
			f.events = append(f.events, key)
			if err := f.fail[key]; err != nil {
				return mountRoot{}, err
			}
			if result, ok := f.fstatResults[f.fstatCalls]; ok {
				return result, nil
			}
			return f.root, nil
		},
		fchown: func(fd, uid, gid int) error {
			f.events = append(f.events, "fchown")
			f.fchownFDs = append(f.fchownFDs, fd)
			if err := f.fail["fchown"]; err != nil {
				return err
			}
			f.root.uid, f.root.gid = uid, gid
			return nil
		},
		close: func(fd int) error {
			f.events = append(f.events, "close")
			f.closeCalls++
			return f.fail["close"]
		},
		setgroups: func(groups []int) error {
			f.events = append(f.events, "setgroups")
			if err := f.fail["setgroups"]; err != nil {
				return err
			}
			f.groups = append([]int(nil), groups...)
			return nil
		},
		setgid: func(gid int) error {
			f.events = append(f.events, "setgid")
			if err := f.fail["setgid"]; err != nil {
				return err
			}
			f.gid, f.egID = gid, gid
			return nil
		},
		setuid: func(uid int) error {
			if uid == 0 {
				f.events = append(f.events, "setuid:root")
				if !f.allowRegain {
					return syscall.EPERM
				}
				f.uid, f.euid = 0, 0
				return nil
			}
			f.events = append(f.events, "setuid:target")
			if err := f.fail["setuid"]; err != nil {
				return err
			}
			f.uid, f.euid = uid, uid
			return nil
		},
		getuid:  func() int { return f.uid },
		geteuid: func() int { return f.euid },
		getgid:  func() int { return f.gid },
		getegid: func() int { return f.egID },
		getgroups: func() ([]int, error) {
			if err := f.fail["getgroups"]; err != nil {
				return nil, err
			}
			return append([]int(nil), f.groups...), nil
		},
		fatal: func(err error) { f.fatalErr = err },
	}
}

func TestPrepareBootstrapRequiresInitialRootIdentityBeforeClassifier(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeSystem)
	}{
		{name: "real uid", mutate: func(f *fakeSystem) { f.uid = 1 }},
		{name: "effective uid", mutate: func(f *fakeSystem) { f.euid = 1 }},
		{name: "real gid", mutate: func(f *fakeSystem) { f.gid = 1 }},
		{name: "effective gid", mutate: func(f *fakeSystem) { f.egID = 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeSystem(0, 0)
			tt.mutate(fake)
			classified := false
			err := prepareBootstrap("/mount", testUID, testGID, func() error {
				classified = true
				return nil
			}, fake.ops())
			if err == nil || !strings.Contains(err.Error(), "initial process identity must be root") {
				t.Fatalf("prepareBootstrap() error = %v, want initial-root rejection", err)
			}
			if classified {
				t.Fatal("classifier ran for non-root initial identity")
			}
			if len(fake.events) != 0 {
				t.Fatalf("operations = %v, want none", fake.events)
			}
		})
	}
}

func TestPrepareBootstrapRootOwnedDescriptorOrdering(t *testing.T) {
	fake := newFakeSystem(0, 0)
	err := prepareBootstrap("/mount", testUID, testGID, func() error {
		fake.events = append(fake.events, "classify")
		return nil
	}, fake.ops())
	if err != nil {
		t.Fatalf("prepareBootstrap() error = %v", err)
	}
	want := []string{"open:/mount", "fstat:1", "classify", "fstat:2", "fchown", "fstat:3", "setgroups", "setgid", "setuid:target", "setuid:root", "close"}
	if !reflect.DeepEqual(fake.events, want) {
		t.Fatalf("events = %v, want %v", fake.events, want)
	}
	if !reflect.DeepEqual(fake.fchownFDs, []int{testFD}) {
		t.Fatalf("fchown descriptors = %v, want exact open descriptor", fake.fchownFDs)
	}
}

func TestPrepareBootstrapAlreadyTargetOwnedSkipsOwnershipMutation(t *testing.T) {
	fake := newFakeSystem(testUID, testGID)
	err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, fake.ops())
	if err != nil {
		t.Fatalf("prepareBootstrap() error = %v", err)
	}
	if len(fake.fchownFDs) != 0 {
		t.Fatalf("fchown descriptors = %v, want none", fake.fchownFDs)
	}
	if fake.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", fake.closeCalls)
	}
}

func TestPrepareBootstrapClassificationFailureHasNoMutationAndCloses(t *testing.T) {
	fake := newFakeSystem(0, 0)
	classifyErr := errors.New("not approved ingress")
	err := prepareBootstrap("/mount", testUID, testGID, func() error {
		fake.events = append(fake.events, "classify")
		return classifyErr
	}, fake.ops())
	if !errors.Is(err, classifyErr) {
		t.Fatalf("prepareBootstrap() error = %v, want classification error", err)
	}
	if got := mutationEvents(fake.events); len(got) != 0 {
		t.Fatalf("mutation events = %v, want none", got)
	}
	want := []string{"open:/mount", "fstat:1", "classify", "close"}
	if !reflect.DeepEqual(fake.events, want) {
		t.Fatalf("events = %v, want %v", fake.events, want)
	}
}

func TestPrepareBootstrapDetectsDescriptorChangeDuringClassification(t *testing.T) {
	tests := []struct {
		name   string
		change func(mountRoot) mountRoot
	}{
		{name: "device", change: func(root mountRoot) mountRoot { root.dev++; return root }},
		{name: "inode", change: func(root mountRoot) mountRoot { root.ino++; return root }},
		{name: "owner", change: func(root mountRoot) mountRoot { root.uid++; return root }},
		{name: "type", change: func(root mountRoot) mountRoot { root.dir = false; return root }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeSystem(0, 0)
			fake.fstatResults[2] = tt.change(fake.root)
			err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, fake.ops())
			if !errors.Is(err, ErrUnsafeOwnership) {
				t.Fatalf("prepareBootstrap() error = %v, want ErrUnsafeOwnership", err)
			}
			if got := mutationEvents(fake.events); len(got) != 0 {
				t.Fatalf("mutation events = %v, want none", got)
			}
			if fake.closeCalls != 1 {
				t.Fatalf("close calls = %d, want 1", fake.closeCalls)
			}
		})
	}
}

func TestPrepareBootstrapDetectsDescriptorChangeAfterOwnershipValidation(t *testing.T) {
	fake := newFakeSystem(0, 0)
	changed := fake.root
	changed.uid, changed.gid = testUID, testGID
	changed.ino++
	fake.fstatResults[3] = changed
	err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, fake.ops())
	if !errors.Is(err, ErrUnsafeOwnership) {
		t.Fatalf("prepareBootstrap() error = %v, want ErrUnsafeOwnership", err)
	}
	if fake.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", fake.closeCalls)
	}
}

func TestPrepareBootstrapRejectsUnsafeOwnerAndNonDirectory(t *testing.T) {
	tests := []mountRoot{
		{uid: 0, gid: testGID, dir: true, dev: 7, ino: 11},
		{uid: testUID, gid: 0, dir: true, dev: 7, ino: 11},
		{uid: 1000, gid: 1000, dir: true, dev: 7, ino: 11},
		{uid: 0, gid: 0, dir: false, dev: 7, ino: 11},
	}
	for _, root := range tests {
		fake := newFakeSystem(root.uid, root.gid)
		fake.root = root
		err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, fake.ops())
		if !errors.Is(err, ErrUnsafeOwnership) {
			t.Fatalf("root %+v: error = %v, want ErrUnsafeOwnership", root, err)
		}
		if got := mutationEvents(fake.events); len(got) != 0 {
			t.Fatalf("root %+v: mutation events = %v", root, got)
		}
		if fake.closeCalls != 1 {
			t.Fatalf("root %+v: close calls = %d, want 1", root, fake.closeCalls)
		}
	}
}

func TestPrepareBootstrapOperationFailuresStopAndClose(t *testing.T) {
	tests := []string{"open", "fstat:1", "fstat:2", "fchown", "fstat:3", "setgroups", "setgid", "setuid"}
	for _, operation := range tests {
		t.Run(operation, func(t *testing.T) {
			fake := newFakeSystem(0, 0)
			injected := errors.New("injected failure")
			fake.fail[operation] = injected
			err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, fake.ops())
			if !errors.Is(err, injected) {
				t.Fatalf("prepareBootstrap() error = %v, want injected failure", err)
			}
			wantClose := 1
			if operation == "open" {
				wantClose = 0
			}
			if fake.closeCalls != wantClose {
				t.Fatalf("close calls = %d, want %d; events=%v", fake.closeCalls, wantClose, fake.events)
			}
		})
	}
}

func TestPrepareBootstrapCloseFailureIsReturned(t *testing.T) {
	fake := newFakeSystem(testUID, testGID)
	closeErr := errors.New("close failed")
	fake.fail["close"] = closeErr
	err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, fake.ops())
	if !errors.Is(err, closeErr) {
		t.Fatalf("prepareBootstrap() error = %v, want close failure", err)
	}
}

func TestPrepareBootstrapVerificationFailurePreventsRootProbe(t *testing.T) {
	fake := newFakeSystem(testUID, testGID)
	ops := fake.ops()
	baseGeteuid := ops.geteuid
	calls := 0
	ops.geteuid = func() int {
		calls++
		if calls > 1 {
			return testUID + 1
		}
		return baseGeteuid()
	}
	err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, ops)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("prepareBootstrap() error = %v, want ErrIdentityMismatch", err)
	}
	if contains(fake.events, "setuid:root") {
		t.Fatalf("root regain probe ran before identity verification: %v", fake.events)
	}
}

func TestPrepareBootstrapSuccessfulRootRegainIsRecoveredAndRejected(t *testing.T) {
	fake := newFakeSystem(testUID, testGID)
	fake.allowRegain = true
	err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, fake.ops())
	if !errors.Is(err, ErrRootRegained) {
		t.Fatalf("prepareBootstrap() error = %v, want ErrRootRegained", err)
	}
	if fake.uid != testUID || fake.euid != testUID || fake.gid != testGID || fake.egID != testGID || len(fake.groups) != 0 {
		t.Fatalf("unsafe recovered identity: uid=%d euid=%d gid=%d egid=%d groups=%v", fake.uid, fake.euid, fake.gid, fake.egID, fake.groups)
	}
	if fake.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", fake.closeCalls)
	}
}

func TestPrepareBootstrapRootRegainRecoveryFailureIsFatal(t *testing.T) {
	fake := newFakeSystem(testUID, testGID)
	fake.allowRegain = true
	calls := 0
	ops := fake.ops()
	baseSetgroups := ops.setgroups
	ops.setgroups = func(groups []int) error {
		calls++
		if calls == 2 {
			return errors.New("recovery denied")
		}
		return baseSetgroups(groups)
	}
	err := prepareBootstrap("/mount", testUID, testGID, func() error { return nil }, ops)
	if !errors.Is(err, ErrRootRegained) || fake.fatalErr == nil {
		t.Fatalf("error=%v fatal=%v, want fatal root-regain failure", err, fake.fatalErr)
	}
}

func TestRequireRuntimeIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeSystem)
		fail   string
		wantOK bool
	}{
		{name: "exact identity", wantOK: true},
		{name: "real uid", mutate: func(f *fakeSystem) { f.uid++ }},
		{name: "effective uid", mutate: func(f *fakeSystem) { f.euid++ }},
		{name: "real gid", mutate: func(f *fakeSystem) { f.gid++ }},
		{name: "effective gid", mutate: func(f *fakeSystem) { f.egID++ }},
		{name: "supplementary group", mutate: func(f *fakeSystem) { f.groups = []int{testGID} }},
		{name: "groups read failure", fail: "getgroups"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeSystem(testUID, testGID)
			fake.uid, fake.euid = testUID, testUID
			fake.gid, fake.egID = testGID, testGID
			fake.groups = nil
			if tt.mutate != nil {
				tt.mutate(fake)
			}
			if tt.fail != "" {
				fake.fail[tt.fail] = errors.New("injected failure")
			}
			err := requireRuntimeIdentity(testUID, testGID, fake.ops())
			if tt.wantOK && err != nil {
				t.Fatalf("requireRuntimeIdentity() error = %v", err)
			}
			if !tt.wantOK && err == nil {
				t.Fatal("requireRuntimeIdentity() error = nil, want failure")
			}
		})
	}
}

func mutationEvents(events []string) []string {
	var mutations []string
	for _, event := range events {
		if event == "fchown" || event == "setgroups" || event == "setgid" || strings.HasPrefix(event, "setuid:") {
			mutations = append(mutations, event)
		}
	}
	return mutations
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
