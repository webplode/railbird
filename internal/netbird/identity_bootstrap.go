package netbird

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	bootstrapFormatVersion = 2
	finalStateDirName      = "netbird"
	bootstrapJournalName   = ".bootstrap-journal.json"
	bootstrapReceiptName   = ".bootstrap-receipt.json"
)

type BootstrapPhase string

const (
	PhaseAllocated BootstrapPhase = "allocated"
	PhasePrepared  BootstrapPhase = "prepared"
	PhaseVerified  BootstrapPhase = "verified"
)

type BootstrapJournal struct {
	Version       int            `json:"version"`
	AttemptID     string         `json:"attempt_id"`
	Phase         BootstrapPhase `json:"phase"`
	PublicKey     string         `json:"public_key,omitempty"`
	ProfileDigest string         `json:"profile_digest"`
}

type BootstrapReceipt struct {
	Version   int    `json:"version"`
	AttemptID string `json:"attempt_id"`
	PublicKey string `json:"public_key"`
}

type BootstrapAction string

const (
	BootstrapCreate           BootstrapAction = "create"
	BootstrapReplaceAllocated BootstrapAction = "replace-allocated"
	BootstrapResume           BootstrapAction = "resume-prepared"
	BootstrapPromote          BootstrapAction = "promote-verified"
	BootstrapFinalize         BootstrapAction = "finalize"
	BootstrapManualRepair     BootstrapAction = "manual-repair"
)

type BootstrapClassification struct {
	Action        BootstrapAction
	StateDir      string
	AttemptID     string
	PublicKey     string
	ProfileDigest string
	HasReceipt    bool
	stateFile     os.FileInfo
}

// ClassifyBootstrapFilesystem selects exactly one BOOT-FS action without
// following symlinks or mutating any state.
func ClassifyBootstrapFilesystem(root string, expectedUID, expectedGID int) (BootstrapClassification, error) {
	fail := func(err error) (BootstrapClassification, error) {
		return BootstrapClassification{Action: BootstrapManualRepair}, fmt.Errorf("bootstrap state requires manual repair: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fail(err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return fail(fmt.Errorf("mount root is not a real directory"))
	}
	if uid, gid, ok := fileOwner(rootInfo); ok && !((uid == 0 && gid == 0) || (uid == expectedUID && gid == expectedGID)) {
		return fail(fmt.Errorf("mount-root owner %d:%d is neither root:root nor runtime %d:%d", uid, gid, expectedUID, expectedGID))
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fail(err)
	}
	if len(entries) == 0 {
		return BootstrapClassification{Action: BootstrapCreate}, nil
	}

	var final string
	var candidates []string
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == finalStateDirName:
			final = filepath.Join(root, name)
		case strings.HasPrefix(name, ".bootstrap-"):
			candidates = append(candidates, filepath.Join(root, name))
		default:
			return fail(fmt.Errorf("unsafe mount-root entry %q", name))
		}
	}
	if final != "" && len(candidates) != 0 || len(candidates) > 1 {
		return fail(fmt.Errorf("conflicting or multiple identity directories"))
	}
	if final != "" {
		classification, err := classifyStateDir(final, rootInfo, expectedUID, expectedGID, true)
		if err != nil || classification.Action != BootstrapFinalize {
			if err == nil {
				err = fmt.Errorf("final identity is incomplete")
			}
			return fail(err)
		}
		return classification, nil
	}
	if len(candidates) != 1 {
		return fail(fmt.Errorf("ambiguous bootstrap contents"))
	}
	classification, err := classifyStateDir(candidates[0], rootInfo, expectedUID, expectedGID, false)
	if err != nil {
		return fail(err)
	}
	return classification, nil
}

func classifyStateDir(dir string, mountRootInfo os.FileInfo, expectedUID, expectedGID int, final bool) (BootstrapClassification, error) {
	stateInfo, err := os.Lstat(dir)
	if err != nil {
		return BootstrapClassification{}, err
	}
	if err := validateTree(dir, mountRootInfo, expectedUID, expectedGID); err != nil {
		return BootstrapClassification{}, err
	}
	j, err := ReadBootstrapJournal(dir)
	if err != nil {
		return BootstrapClassification{}, err
	}
	result := BootstrapClassification{
		StateDir:      dir,
		AttemptID:     j.AttemptID,
		PublicKey:     j.PublicKey,
		ProfileDigest: j.ProfileDigest,
		stateFile:     stateInfo,
	}
	if final {
		if j.Phase != PhaseVerified {
			return result, fmt.Errorf("final journal is not verified")
		}
		if err := validateStateDirContents(dir, map[string]bool{
			bootstrapJournalName: true,
			bootstrapReceiptName: true,
			"config.json":        true,
			"state.json":         true,
		}); err != nil {
			return result, err
		}
		receipt, err := ReadBootstrapReceipt(dir)
		if err != nil || receipt.AttemptID != j.AttemptID || receipt.PublicKey != j.PublicKey {
			return result, fmt.Errorf("final receipt does not match journal")
		}
		if _, err := loadPersistentIdentity(dir, j.PublicKey, expectedUID, expectedGID); err != nil {
			return result, err
		}
		result.Action, result.HasReceipt = BootstrapFinalize, true
		return result, nil
	}

	suffix := strings.TrimPrefix(filepath.Base(dir), ".bootstrap-")
	if suffix == "" || suffix != j.AttemptID {
		return result, fmt.Errorf("candidate attempt id does not match directory")
	}
	switch j.Phase {
	case PhaseAllocated:
		if j.PublicKey != "" {
			return result, fmt.Errorf("allocated journal contains public key")
		}
		if _, err := os.Lstat(filepath.Join(dir, bootstrapReceiptName)); err == nil {
			return result, fmt.Errorf("allocated candidate contains receipt")
		} else if !os.IsNotExist(err) {
			return result, err
		}
		if err := validateStateDirContents(dir, map[string]bool{
			bootstrapJournalName: true,
			"config.json":        true,
		}); err != nil {
			return result, err
		}
		if _, err := os.Lstat(filepath.Join(dir, "config.json")); err == nil {
			if _, err := loadPersistentIdentity(dir, "", expectedUID, expectedGID); err != nil {
				return result, fmt.Errorf("allocated config identity is unsafe: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return result, err
		}
		result.Action = BootstrapReplaceAllocated
	case PhasePrepared:
		if _, err := os.Lstat(filepath.Join(dir, bootstrapReceiptName)); err == nil {
			return result, fmt.Errorf("prepared candidate contains premature receipt")
		} else if !os.IsNotExist(err) {
			return result, err
		}
		if err := validateStateDirContents(dir, map[string]bool{
			bootstrapJournalName: true,
			"config.json":        true,
			"state.json":         true,
		}); err != nil {
			return result, err
		}
		if _, err := loadPersistentIdentity(dir, j.PublicKey, expectedUID, expectedGID); err != nil {
			return result, err
		}
		result.Action = BootstrapResume
	case PhaseVerified:
		if err := validateStateDirContents(dir, map[string]bool{
			bootstrapJournalName: true,
			bootstrapReceiptName: true,
			"config.json":        true,
			"state.json":         true,
		}); err != nil {
			return result, err
		}
		if _, err := loadPersistentIdentity(dir, j.PublicKey, expectedUID, expectedGID); err != nil {
			return result, err
		}
		if receipt, err := ReadBootstrapReceipt(dir); err == nil {
			if receipt.AttemptID != j.AttemptID || receipt.PublicKey != j.PublicKey {
				return result, fmt.Errorf("receipt does not match journal")
			}
			result.HasReceipt = true
		} else if !os.IsNotExist(unwrapPathError(err)) {
			return result, err
		}
		result.Action = BootstrapPromote
	default:
		return result, fmt.Errorf("invalid bootstrap phase")
	}
	return result, nil
}

func validateTree(root string, mountRootInfo os.FileInfo, expectedUID, expectedGID int) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return validateTreeEntry(path, info, expectedUID, expectedGID, mountRootInfo)
	})
}

func validateTreeEntry(path string, info os.FileInfo, expectedUID, expectedGID int, rootInfo os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink is forbidden: %s", path)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("special file is forbidden: %s", path)
	}
	if hasSpecialPermissionBits(info.Mode()) || info.IsDir() && info.Mode().Perm()&^os.FileMode(0o700) != 0 || info.Mode().IsRegular() && info.Mode().Perm()&^os.FileMode(0o600) != 0 {
		return fmt.Errorf("unsafe permissions: %s", path)
	}
	if err := requireOwner(info, expectedUID, expectedGID); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	rootStat, rootOK := rootInfo.Sys().(*syscall.Stat_t)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if rootOK && ok && rootStat.Dev != stat.Dev {
		return fmt.Errorf("entry crosses filesystem: %s", path)
	}
	return nil
}

func validateStateDirContents(dir string, allowed map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return fmt.Errorf("unexpected identity-state entry %q", entry.Name())
		}
	}
	return nil
}

func WriteBootstrapJournal(dir string, journal BootstrapJournal) error {
	if err := validateJournal(journal); err != nil {
		return err
	}
	return atomicWriteJSON(dir, bootstrapJournalName, journal)
}

func ReadBootstrapJournal(dir string) (BootstrapJournal, error) {
	var journal BootstrapJournal
	if err := readStrictJSON(filepath.Join(dir, bootstrapJournalName), &journal); err != nil {
		return journal, err
	}
	return journal, validateJournal(journal)
}

func WriteBootstrapReceipt(dir string, receipt BootstrapReceipt) error {
	if receipt.Version != bootstrapFormatVersion || !validAttemptID(receipt.AttemptID) || !validPublicKey(receipt.PublicKey) {
		return fmt.Errorf("invalid bootstrap receipt")
	}
	return atomicWriteJSON(dir, bootstrapReceiptName, receipt)
}

func ReadBootstrapReceipt(dir string) (BootstrapReceipt, error) {
	var receipt BootstrapReceipt
	if err := readStrictJSON(filepath.Join(dir, bootstrapReceiptName), &receipt); err != nil {
		return receipt, err
	}
	if receipt.Version != bootstrapFormatVersion || !validAttemptID(receipt.AttemptID) || !validPublicKey(receipt.PublicKey) {
		return receipt, fmt.Errorf("invalid bootstrap receipt")
	}
	return receipt, nil
}

func validateJournal(j BootstrapJournal) error {
	if j.Version != bootstrapFormatVersion || !validAttemptID(j.AttemptID) {
		return fmt.Errorf("invalid bootstrap journal")
	}
	if !validProfileDigest(j.ProfileDigest) {
		return fmt.Errorf("invalid bootstrap journal profile digest")
	}
	if j.Phase == PhaseAllocated && j.PublicKey != "" || (j.Phase == PhasePrepared || j.Phase == PhaseVerified) && j.PublicKey == "" {
		return fmt.Errorf("invalid bootstrap journal phase data")
	}
	if j.Phase != PhaseAllocated && !validPublicKey(j.PublicKey) {
		return fmt.Errorf("invalid bootstrap journal public key")
	}
	if j.Phase != PhaseAllocated && j.Phase != PhasePrepared && j.Phase != PhaseVerified {
		return fmt.Errorf("invalid bootstrap journal phase")
	}
	return nil
}

func validProfileDigest(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}

func validPublicKey(publicKey string) bool {
	_, err := wgtypes.ParseKey(publicKey)
	return err == nil
}

func validAttemptID(attemptID string) bool {
	if len(attemptID) != 32 {
		return false
	}
	_, err := hex.DecodeString(attemptID)
	return err == nil
}

func atomicWriteJSON(dir, name string, value any) (retErr error) {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		if retErr != nil {
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := json.NewEncoder(tmp).Encode(value); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}

func readStrictJSON(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing journal data")
	}
	return nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func unwrapPathError(err error) error {
	if pathErr, ok := err.(*os.PathError); ok {
		return pathErr.Err
	}
	return err
}

type BootstrapClientOptions struct {
	StateDir string
	SetupKey string
}

type BootstrapClient interface {
	Start(context.Context) error
	Status(context.Context) (BootstrapStatus, error)
	Stop(context.Context) error
}

type BootstrapStatus struct {
	PublicKey           string
	ManagementConnected bool
	SignalConnected     bool
}

type BootstrapClientFactory interface {
	New(context.Context, BootstrapClientOptions) (BootstrapClient, error)
}

// RunBootstrap performs only the local crash-safe identity transaction. The
// injected factory owns NetBird construction and remote effects. A prepared
// transaction is bound to the exact remote-effect profile that created it.
func RunBootstrap(ctx context.Context, root string, opts Options, expectedUID, expectedGID int, factory BootstrapClientFactory) (string, error) {
	classification, err := ClassifyBootstrapFilesystem(root, expectedUID, expectedGID)
	if err != nil {
		return "", err
	}
	if classification.Action == BootstrapFinalize {
		return finalizeExistingBootstrap(root, classification)
	}
	if classification.Action == BootstrapManualRepair {
		return "", fmt.Errorf("bootstrap state requires manual repair")
	}
	if classification.Action == BootstrapReplaceAllocated {
		if err := removeClassifiedState(root, classification); err != nil {
			return "", err
		}
		classification.Action = BootstrapCreate
	}
	if classification.Action == BootstrapPromote {
		return promoteBootstrap(root, classification)
	}

	profileDigest, err := bootstrapProfileDigest(opts)
	if err != nil {
		return "", err
	}
	if classification.Action == BootstrapResume && subtle.ConstantTimeCompare(
		[]byte(classification.ProfileDigest),
		[]byte(profileDigest),
	) != 1 {
		return "", fmt.Errorf("prepared bootstrap profile does not match the original transaction")
	}
	if classification.Action == BootstrapCreate {
		attemptID, err := newAttemptID()
		if err != nil {
			return "", err
		}
		classification = BootstrapClassification{
			Action:        BootstrapCreate,
			AttemptID:     attemptID,
			StateDir:      filepath.Join(root, ".bootstrap-"+attemptID),
			ProfileDigest: profileDigest,
		}
		rootHandle, err := os.OpenRoot(root)
		if err != nil {
			return "", err
		}
		candidateName := filepath.Base(classification.StateDir)
		if err := rootHandle.Mkdir(candidateName, 0o700); err != nil {
			rootHandle.Close()
			return "", err
		}
		classification.stateFile, err = rootHandle.Lstat(candidateName)
		if err != nil {
			rootHandle.Close()
			return "", err
		}
		if err := syncOpenedRoot(rootHandle); err != nil {
			rootHandle.Close()
			return "", err
		}
		if err := rootHandle.Close(); err != nil {
			return "", err
		}
		if err := WriteBootstrapJournal(classification.StateDir, BootstrapJournal{
			Version:       bootstrapFormatVersion,
			AttemptID:     attemptID,
			Phase:         PhaseAllocated,
			ProfileDigest: profileDigest,
		}); err != nil {
			return "", err
		}
	}
	if factory == nil {
		return "", fmt.Errorf("bootstrap setup key and client factory are required")
	}

	client, err := factory.New(ctx, BootstrapClientOptions{StateDir: classification.StateDir, SetupKey: opts.SetupKey})
	if err != nil {
		return "", err
	}
	identity, err := loadPersistentIdentity(classification.StateDir, classification.PublicKey, expectedUID, expectedGID)
	if err != nil {
		return "", err
	}
	if classification.Action == BootstrapCreate {
		classification.PublicKey = identity.PublicKey
		if err := syncTree(classification.StateDir); err != nil {
			return "", err
		}
		if err := WriteBootstrapJournal(classification.StateDir, BootstrapJournal{
			Version:       bootstrapFormatVersion,
			AttemptID:     classification.AttemptID,
			Phase:         PhasePrepared,
			PublicKey:     identity.PublicKey,
			ProfileDigest: classification.ProfileDigest,
		}); err != nil {
			return "", err
		}
	}
	if err := client.Start(ctx); err != nil {
		_ = stopBootstrapClient(client)
		return "", err
	}
	status, err := WaitForConnected(ctx, func() (BootstrapStatus, error) {
		return client.Status(ctx)
	}, 100*time.Millisecond)
	statusKey, keyErr := wgtypes.ParseKey(status.PublicKey)
	identityKey, identityErr := wgtypes.ParseKey(identity.PublicKey)
	if err != nil || keyErr != nil || identityErr != nil || !status.ManagementConnected || !status.SignalConnected || subtle.ConstantTimeCompare(statusKey[:], identityKey[:]) != 1 {
		_ = stopBootstrapClient(client)
		return "", fmt.Errorf("bootstrap client did not reach connected expected identity")
	}
	if err := stopBootstrapClient(client); err != nil {
		return "", err
	}
	verified := BootstrapJournal{
		Version:       bootstrapFormatVersion,
		AttemptID:     classification.AttemptID,
		Phase:         PhaseVerified,
		PublicKey:     identity.PublicKey,
		ProfileDigest: classification.ProfileDigest,
	}
	if err := WriteBootstrapJournal(classification.StateDir, verified); err != nil {
		return "", err
	}
	if err := WriteBootstrapReceipt(classification.StateDir, BootstrapReceipt{Version: bootstrapFormatVersion, AttemptID: verified.AttemptID, PublicKey: verified.PublicKey}); err != nil {
		return "", err
	}
	classification.PublicKey = identity.PublicKey
	return promoteBootstrap(root, classification)
}

func bootstrapProfileDigest(opts Options) (string, error) {
	if strings.TrimSpace(opts.SetupKey) == "" || strings.TrimSpace(opts.ManagementURL) == "" ||
		strings.TrimSpace(opts.DeviceName) == "" || string(opts.Mode) == "" {
		return "", fmt.Errorf("complete bootstrap profile and client factory are required")
	}
	profile := struct {
		Version       int      `json:"version"`
		SetupKey      string   `json:"setup_key"`
		ManagementURL string   `json:"management_url"`
		DeviceName    string   `json:"device_name"`
		DNSLabels     []string `json:"dns_labels"`
		Mode          string   `json:"mode"`
	}{
		Version:       1,
		SetupKey:      opts.SetupKey,
		ManagementURL: opts.ManagementURL,
		DeviceName:    opts.DeviceName,
		DNSLabels:     append([]string(nil), opts.DNSLabels...),
		Mode:          string(opts.Mode),
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		return "", fmt.Errorf("encode bootstrap profile: %w", err)
	}
	digest := sha256.Sum256(append([]byte("railbird/bootstrap-profile/v1\x00"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func stopBootstrapClient(client BootstrapClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return client.Stop(ctx)
}

func promoteBootstrap(root string, classification BootstrapClassification) (string, error) {
	if !classification.HasReceipt {
		if err := WriteBootstrapReceipt(classification.StateDir, BootstrapReceipt{Version: bootstrapFormatVersion, AttemptID: classification.AttemptID, PublicKey: classification.PublicKey}); err != nil {
			return "", err
		}
	}
	if err := syncTree(classification.StateDir); err != nil {
		return "", err
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return "", err
	}
	defer rootHandle.Close()
	if err := verifyClassifiedState(rootHandle, classification); err != nil {
		return "", err
	}
	if err := rootHandle.Rename(filepath.Base(classification.StateDir), finalStateDirName); err != nil {
		return "", err
	}
	if err := syncOpenedRoot(rootHandle); err != nil {
		return "", err
	}
	return classification.PublicKey, nil
}

func finalizeExistingBootstrap(root string, classification BootstrapClassification) (string, error) {
	if err := syncTree(classification.StateDir); err != nil {
		return "", err
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return "", err
	}
	defer rootHandle.Close()
	if err := verifyClassifiedState(rootHandle, classification); err != nil {
		return "", err
	}
	if err := syncOpenedRoot(rootHandle); err != nil {
		return "", err
	}
	return classification.PublicKey, nil
}

func removeClassifiedState(root string, classification BootstrapClassification) error {
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootHandle.Close()
	if err := verifyClassifiedState(rootHandle, classification); err != nil {
		return err
	}
	if err := rootHandle.RemoveAll(filepath.Base(classification.StateDir)); err != nil {
		return err
	}
	return syncOpenedRoot(rootHandle)
}

func verifyClassifiedState(root *os.Root, classification BootstrapClassification) error {
	current, err := root.Lstat(filepath.Base(classification.StateDir))
	if err != nil {
		return err
	}
	if classification.stateFile == nil || !os.SameFile(classification.stateFile, current) {
		return fmt.Errorf("classified identity directory changed before mutation")
	}
	return nil
}

func syncOpenedRoot(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func syncTree(root string) error {
	var dirs []string
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	}); err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := syncDir(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

func newAttemptID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
