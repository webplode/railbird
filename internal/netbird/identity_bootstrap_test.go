package netbird

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const testAttemptID = "0123456789abcdef0123456789abcdef"

func TestClassifyBootstrapFilesystem(t *testing.T) {
	t.Run("BOOT-FS-01 empty", func(t *testing.T) {
		got, err := ClassifyBootstrapFilesystem(t.TempDir(), os.Geteuid(), os.Getegid())
		if err != nil || got.Action != BootstrapCreate {
			t.Fatalf("classification = %#v, %v", got, err)
		}
	})

	t.Run("BOOT-FS-02 allocated", func(t *testing.T) {
		root, candidate := testCandidate(t, PhaseAllocated, false)
		got, err := ClassifyBootstrapFilesystem(root, os.Geteuid(), os.Getegid())
		if err != nil || got.Action != BootstrapReplaceAllocated || got.StateDir != candidate {
			t.Fatalf("classification = %#v, %v", got, err)
		}
	})

	t.Run("BOOT-FS-03 prepared", func(t *testing.T) {
		root, candidate := testCandidate(t, PhasePrepared, false)
		got, err := ClassifyBootstrapFilesystem(root, os.Geteuid(), os.Getegid())
		if err != nil || got.Action != BootstrapResume || got.StateDir != candidate || got.PublicKey == "" {
			t.Fatalf("classification = %#v, %v", got, err)
		}
	})

	t.Run("BOOT-FS-04 receipt-bearing final", func(t *testing.T) {
		root := t.TempDir()
		final := filepath.Join(root, finalStateDirName)
		if err := os.Mkdir(final, 0o700); err != nil {
			t.Fatal(err)
		}
		key := writeTestConfig(t, final)
		journal := BootstrapJournal{
			Version:       bootstrapFormatVersion,
			AttemptID:     testAttemptID,
			Phase:         PhaseVerified,
			PublicKey:     key.PublicKey().String(),
			ProfileDigest: testProfileDigest(t, testBootstrapOptions("original-setup-secret")),
		}
		if err := WriteBootstrapJournal(final, journal); err != nil {
			t.Fatal(err)
		}
		if err := WriteBootstrapReceipt(final, BootstrapReceipt{Version: bootstrapFormatVersion, AttemptID: journal.AttemptID, PublicKey: journal.PublicKey}); err != nil {
			t.Fatal(err)
		}
		got, err := ClassifyBootstrapFilesystem(root, os.Geteuid(), os.Getegid())
		if err != nil || got.Action != BootstrapFinalize || got.PublicKey != journal.PublicKey {
			t.Fatalf("classification = %#v, %v", got, err)
		}
	})

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{name: "multiple candidates", setup: func(t *testing.T) string {
			root, _ := testCandidate(t, PhaseAllocated, false)
			if err := os.Mkdir(filepath.Join(root, ".bootstrap-other"), 0o700); err != nil {
				t.Fatal(err)
			}
			return root
		}},
		{name: "allocated with arbitrary file", setup: func(t *testing.T) string {
			root, candidate := testCandidate(t, PhaseAllocated, false)
			writeFile(t, filepath.Join(candidate, "unknown"), nil, 0o600)
			return root
		}},
		{name: "allocated with invalid config identity", setup: func(t *testing.T) string {
			root, candidate := testCandidate(t, PhaseAllocated, false)
			writeFile(t, filepath.Join(candidate, "config.json"), []byte(`{"PrivateKey":"invalid"}`), 0o600)
			return root
		}},
		{name: "incomplete final", setup: func(t *testing.T) string {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, finalStateDirName), 0o700); err != nil {
				t.Fatal(err)
			}
			return root
		}},
		{name: "conflicting final and candidate", setup: func(t *testing.T) string {
			root, _ := testCandidate(t, PhasePrepared, false)
			if err := os.Mkdir(filepath.Join(root, finalStateDirName), 0o700); err != nil {
				t.Fatal(err)
			}
			return root
		}},
	} {
		t.Run("BOOT-FS-05 "+tc.name, func(t *testing.T) {
			got, err := ClassifyBootstrapFilesystem(tc.setup(t), os.Geteuid(), os.Getegid())
			if err == nil || got.Action != BootstrapManualRepair {
				t.Fatalf("classification = %#v, %v", got, err)
			}
		})
	}
}

func TestBootstrapMetadataWritesUsePrivateModesAndLeaveNoTemporaryFiles(t *testing.T) {
	dir := secureTempDir(t)
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := key.PublicKey().String()
	j := BootstrapJournal{
		Version:       bootstrapFormatVersion,
		AttemptID:     testAttemptID,
		Phase:         PhasePrepared,
		PublicKey:     publicKey,
		ProfileDigest: testProfileDigest(t, testBootstrapOptions("original-setup-secret")),
	}
	if err := WriteBootstrapJournal(dir, j); err != nil {
		t.Fatal(err)
	}
	if err := WriteBootstrapReceipt(dir, BootstrapReceipt{Version: bootstrapFormatVersion, AttemptID: testAttemptID, PublicKey: publicKey}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{bootstrapJournalName, bootstrapReceiptName} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
			t.Fatalf("%s mode = %v", name, info.Mode())
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("metadata directory contains %d entries, want 2", len(entries))
	}
}

func TestRunBootstrapOrdersDurablePreparedBeforeStartAndResumesSameKey(t *testing.T) {
	root := t.TempDir()
	factory := &recordingBootstrapFactory{t: t, expectedPhase: PhaseAllocated}
	publicKey, err := RunBootstrap(context.Background(), root, testBootstrapOptions("setup-secret"), os.Geteuid(), os.Getegid(), factory)
	if err != nil {
		t.Fatalf("RunBootstrap() error = %v", err)
	}
	if publicKey == "" || factory.newCalls != 1 || factory.startCalls != 1 {
		t.Fatalf("result key=%q new=%d start=%d", publicKey, factory.newCalls, factory.startCalls)
	}
	got, err := ClassifyBootstrapFilesystem(root, os.Geteuid(), os.Getegid())
	if err != nil || got.Action != BootstrapFinalize || got.PublicKey != publicKey {
		t.Fatalf("final classification = %#v, %v", got, err)
	}
}

func TestRunBootstrapResumesSamePreparedCandidate(t *testing.T) {
	root, candidate := testCandidate(t, PhasePrepared, false)
	j, err := ReadBootstrapJournal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	factory := &recordingBootstrapFactory{t: t, expectedPhase: PhasePrepared}
	publicKey, err := RunBootstrap(context.Background(), root, testBootstrapOptions("original-setup-secret"), os.Geteuid(), os.Getegid(), factory)
	if err != nil {
		t.Fatalf("RunBootstrap() error = %v", err)
	}
	if publicKey != j.PublicKey || factory.observedDir != candidate {
		t.Fatalf("resumed key=%q dir=%q, want key=%q dir=%q", publicKey, factory.observedDir, j.PublicKey, candidate)
	}
}

func TestRunBootstrapFinalizesCompleteFinalWithoutClientFactory(t *testing.T) {
	root, candidate := testCandidate(t, PhaseVerified, true)
	final := filepath.Join(root, finalStateDirName)
	if err := os.Rename(candidate, final); err != nil {
		t.Fatal(err)
	}
	j, _ := ReadBootstrapJournal(final)
	got, err := RunBootstrap(context.Background(), root, Options{}, os.Geteuid(), os.Getegid(), nil)
	if err != nil || got != j.PublicKey {
		t.Fatalf("RunBootstrap() = %q, %v", got, err)
	}
}

func TestValidateTreeEntryRejectsDifferentMountDevice(t *testing.T) {
	uid, gid := os.Geteuid(), os.Getegid()
	mount := fakeFileInfo{mode: os.ModeDir | 0o700, stat: &syscall.Stat_t{Dev: 1, Uid: uint32(uid), Gid: uint32(gid)}}
	child := fakeFileInfo{mode: 0o600, stat: &syscall.Stat_t{Dev: 2, Uid: uint32(uid), Gid: uint32(gid)}}
	if err := validateTreeEntry("candidate/config.json", child, uid, gid, mount); err == nil {
		t.Fatal("different-device entry accepted")
	}
}

func TestRunBootstrapDisconnectedStatusStopsAndRetainsPreparedCandidate(t *testing.T) {
	root, candidate := testCandidate(t, PhasePrepared, false)
	client := &disconnectedBootstrapClient{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := RunBootstrap(ctx, root, testBootstrapOptions("original-setup-secret"), os.Geteuid(), os.Getegid(), staticBootstrapFactory{client: client})
	if err == nil {
		t.Fatal("RunBootstrap() error = nil")
	}
	if client.stopCalls != 1 || !client.stopHadDeadline {
		t.Fatalf("Stop calls=%d bounded=%v", client.stopCalls, client.stopHadDeadline)
	}
	j, readErr := ReadBootstrapJournal(candidate)
	if readErr != nil || j.Phase != PhasePrepared {
		t.Fatalf("retained journal = %#v, %v", j, readErr)
	}
}

func TestRunBootstrapRejectsPreparedProfileChangesBeforeRemoteEffects(t *testing.T) {
	base := testBootstrapOptions("original-setup-secret")
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "setup key", mutate: func(opts *Options) { opts.SetupKey = "different-setup-secret" }},
		{name: "management URL", mutate: func(opts *Options) { opts.ManagementURL = "https://other-netbird.example.com" }},
		{name: "device name", mutate: func(opts *Options) { opts.DeviceName = "other-ingress" }},
		{name: "DNS labels", mutate: func(opts *Options) { opts.DNSLabels = []string{"other"} }},
		{name: "mode", mutate: func(opts *Options) { opts.Mode = config.ModeEgress }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, candidate := testCandidate(t, PhasePrepared, false)
			changed := base
			changed.DNSLabels = append([]string(nil), base.DNSLabels...)
			tc.mutate(&changed)
			factory := &recordingBootstrapFactory{t: t, expectedPhase: PhasePrepared}

			_, err := RunBootstrap(context.Background(), root, changed, os.Geteuid(), os.Getegid(), factory)
			if err == nil || !strings.Contains(err.Error(), "profile does not match") {
				t.Fatalf("RunBootstrap() error = %v", err)
			}
			if factory.newCalls != 0 || factory.startCalls != 0 {
				t.Fatalf("remote factory calls new=%d start=%d", factory.newCalls, factory.startCalls)
			}
			for _, secret := range []string{base.SetupKey, changed.SetupKey, base.ManagementURL, changed.ManagementURL} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatalf("error exposed profile input %q: %v", secret, err)
				}
			}
			classification, classifyErr := ClassifyBootstrapFilesystem(root, os.Geteuid(), os.Getegid())
			if classifyErr != nil || classification.Action != BootstrapResume || classification.StateDir != candidate {
				t.Fatalf("prepared transaction changed: %#v, %v", classification, classifyErr)
			}
		})
	}
}

func testCandidate(t *testing.T, phase BootstrapPhase, receipt bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	candidate := filepath.Join(root, ".bootstrap-"+testAttemptID)
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	j := BootstrapJournal{
		Version:       bootstrapFormatVersion,
		AttemptID:     testAttemptID,
		Phase:         phase,
		ProfileDigest: testProfileDigest(t, testBootstrapOptions("original-setup-secret")),
	}
	if phase != PhaseAllocated {
		key := writeTestConfig(t, candidate)
		j.PublicKey = key.PublicKey().String()
	}
	if err := WriteBootstrapJournal(candidate, j); err != nil {
		t.Fatal(err)
	}
	if receipt {
		if err := WriteBootstrapReceipt(candidate, BootstrapReceipt{Version: bootstrapFormatVersion, AttemptID: j.AttemptID, PublicKey: j.PublicKey}); err != nil {
			t.Fatal(err)
		}
	}
	return root, candidate
}

func testBootstrapOptions(setupKey string) Options {
	return Options{
		SetupKey:      setupKey,
		ManagementURL: "https://netbird.example.com",
		DeviceName:    "railbird-ingress",
		DNSLabels:     []string{"railbird"},
		Mode:          config.ModeIngress,
	}
}

func testProfileDigest(t *testing.T, opts Options) string {
	t.Helper()
	digest, err := bootstrapProfileDigest(opts)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type recordingBootstrapFactory struct {
	t             *testing.T
	expectedPhase BootstrapPhase
	observedDir   string
	newCalls      int
	startCalls    int
}

func (f *recordingBootstrapFactory) New(_ context.Context, opts BootstrapClientOptions) (BootstrapClient, error) {
	f.newCalls++
	f.observedDir = opts.StateDir
	j, err := ReadBootstrapJournal(opts.StateDir)
	if err != nil || j.Phase != f.expectedPhase {
		f.t.Fatalf("factory.New observed journal %#v, %v", j, err)
	}
	publicKey := j.PublicKey
	if j.Phase == PhaseAllocated {
		key := writeTestConfig(f.t, opts.StateDir)
		publicKey = key.PublicKey().String()
	}
	return &recordingBootstrapClient{factory: f, stateDir: opts.StateDir, publicKey: publicKey}, nil
}

type recordingBootstrapClient struct {
	factory   *recordingBootstrapFactory
	stateDir  string
	publicKey string
}

func (c *recordingBootstrapClient) Start(context.Context) error {
	c.factory.startCalls++
	j, err := ReadBootstrapJournal(c.stateDir)
	if err != nil || j.Phase != PhasePrepared || j.PublicKey != c.publicKey {
		c.factory.t.Fatalf("Start observed journal %#v, %v", j, err)
	}
	return nil
}
func (c *recordingBootstrapClient) Status(context.Context) (BootstrapStatus, error) {
	return BootstrapStatus{PublicKey: c.publicKey, ManagementConnected: true, SignalConnected: true}, nil
}
func (c *recordingBootstrapClient) Stop(context.Context) error { return nil }

type staticBootstrapFactory struct{ client BootstrapClient }

func (f staticBootstrapFactory) New(context.Context, BootstrapClientOptions) (BootstrapClient, error) {
	return f.client, nil
}

type disconnectedBootstrapClient struct {
	stopCalls       int
	stopHadDeadline bool
}

type fakeFileInfo struct {
	mode os.FileMode
	stat *syscall.Stat_t
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return f.stat }

func (*disconnectedBootstrapClient) Start(context.Context) error { return nil }
func (*disconnectedBootstrapClient) Status(context.Context) (BootstrapStatus, error) {
	return BootstrapStatus{}, nil
}
func (c *disconnectedBootstrapClient) Stop(ctx context.Context) error {
	c.stopCalls++
	_, c.stopHadDeadline = ctx.Deadline()
	return nil
}
