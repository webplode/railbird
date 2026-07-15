package netbird

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PersistentIdentity is the validated local credential passed to NetBird.
type PersistentIdentity struct {
	PrivateKey string
	PublicKey  string
}

// LoadPersistentIdentity validates config.json as the identity root. state.json
// is deliberately ignored: it contains runtime state, not an identity key.
func LoadPersistentIdentity(stateDir, expectedPublicKey string, expectedUID, expectedGID int) (PersistentIdentity, error) {
	return loadPersistentIdentity(stateDir, expectedPublicKey, expectedUID, expectedGID)
}

// LoadPersistentVolumeIdentity validates the serving-only Volume shape. Unlike
// bootstrap classification, the mount root must already belong to the runtime
// UID:GID and contain only one complete receipt-bearing final identity.
func LoadPersistentVolumeIdentity(mountRoot, expectedPublicKey string, expectedUID, expectedGID int) (PersistentIdentity, error) {
	rootInfo, err := os.Lstat(mountRoot)
	if err != nil {
		return PersistentIdentity{}, fmt.Errorf("inspect persistent mount root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return PersistentIdentity{}, fmt.Errorf("persistent mount root must be a real directory")
	}
	if err := requireOwner(rootInfo, expectedUID, expectedGID); err != nil {
		return PersistentIdentity{}, fmt.Errorf("persistent mount root: %w", err)
	}
	classification, err := ClassifyBootstrapFilesystem(mountRoot, expectedUID, expectedGID)
	if err != nil || classification.Action != BootstrapFinalize {
		if err == nil {
			err = fmt.Errorf("persistent volume lacks complete final identity")
		}
		return PersistentIdentity{}, err
	}
	return loadPersistentIdentity(classification.StateDir, expectedPublicKey, expectedUID, expectedGID)
}

func loadPersistentIdentity(stateDir, expectedPublicKey string, expectedUID, expectedGID int) (PersistentIdentity, error) {
	dirInfo, err := os.Lstat(stateDir)
	if err != nil {
		return PersistentIdentity{}, fmt.Errorf("inspect identity directory: %w", err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return PersistentIdentity{}, fmt.Errorf("identity directory must be a real directory")
	}
	if dirInfo.Mode().Perm()&^os.FileMode(0o700) != 0 || hasSpecialPermissionBits(dirInfo.Mode()) {
		return PersistentIdentity{}, fmt.Errorf("identity directory permissions exceed 0700")
	}
	if err := requireOwner(dirInfo, expectedUID, expectedGID); err != nil {
		return PersistentIdentity{}, fmt.Errorf("identity directory: %w", err)
	}

	configPath := filepath.Join(stateDir, "config.json")
	lstat, err := os.Lstat(configPath)
	if err != nil {
		return PersistentIdentity{}, fmt.Errorf("inspect config.json: %w", err)
	}
	if !lstat.Mode().IsRegular() || lstat.Mode()&os.ModeSymlink != 0 {
		return PersistentIdentity{}, fmt.Errorf("config.json must be a regular non-symlink file")
	}
	if lstat.Mode().Perm()&^os.FileMode(0o600) != 0 || hasSpecialPermissionBits(lstat.Mode()) {
		return PersistentIdentity{}, fmt.Errorf("config.json permissions exceed 0600")
	}
	if err := requireOwner(lstat, expectedUID, expectedGID); err != nil {
		return PersistentIdentity{}, fmt.Errorf("config.json: %w", err)
	}

	f, err := os.Open(configPath)
	if err != nil {
		return PersistentIdentity{}, fmt.Errorf("open config.json: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(lstat, opened) {
		return PersistentIdentity{}, fmt.Errorf("config.json changed during validation")
	}
	var cfg struct {
		PrivateKey string
	}
	decoder := json.NewDecoder(io.LimitReader(f, 4<<20))
	if err := decoder.Decode(&cfg); err != nil {
		return PersistentIdentity{}, fmt.Errorf("parse config.json: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return PersistentIdentity{}, fmt.Errorf("parse config.json: trailing data")
	}
	privateKey, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return PersistentIdentity{}, fmt.Errorf("config.json contains invalid private key")
	}
	publicKey := privateKey.PublicKey()
	if expectedPublicKey != "" {
		expected, err := wgtypes.ParseKey(expectedPublicKey)
		if err != nil {
			return PersistentIdentity{}, fmt.Errorf("invalid expected public key")
		}
		if subtle.ConstantTimeCompare(publicKey[:], expected[:]) != 1 {
			return PersistentIdentity{}, fmt.Errorf("persistent identity public key mismatch")
		}
	}
	return PersistentIdentity{PrivateKey: privateKey.String(), PublicKey: publicKey.String()}, nil
}

func hasSpecialPermissionBits(mode os.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
}

func requireOwner(info os.FileInfo, expectedUID, expectedGID int) error {
	if expectedUID < 0 || expectedGID < 0 {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil // Ownership is not exposed on this platform.
	}
	if int(stat.Uid) != expectedUID || int(stat.Gid) != expectedGID {
		return fmt.Errorf("owner %d:%d, want %d:%d", stat.Uid, stat.Gid, expectedUID, expectedGID)
	}
	return nil
}

func fileOwner(info os.FileInfo) (int, int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
