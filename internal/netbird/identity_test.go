package netbird

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLoadPersistentIdentity(t *testing.T) {
	dir := secureTempDir(t)
	privateKey := writeTestConfig(t, dir)
	wantPublic := privateKey.PublicKey().String()

	identity, err := LoadPersistentIdentity(dir, wantPublic, os.Geteuid(), os.Getegid())
	if err != nil {
		t.Fatalf("LoadPersistentIdentity() error = %v", err)
	}
	if identity.PrivateKey != privateKey.String() || identity.PublicKey != wantPublic {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestLoadPersistentIdentityRejectsUnsafeOrIncompleteState(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string) string
	}{
		{name: "state json alone", setup: func(t *testing.T, dir string) string {
			writeFile(t, filepath.Join(dir, "state.json"), []byte(`{}`), 0o600)
			return privateKey.PublicKey().String()
		}},
		{name: "public key mismatch", setup: func(t *testing.T, dir string) string {
			writeTestConfigWithKey(t, dir, privateKey)
			other, _ := wgtypes.GeneratePrivateKey()
			return other.PublicKey().String()
		}},
		{name: "config too permissive", setup: func(t *testing.T, dir string) string {
			writeTestConfigWithKey(t, dir, privateKey)
			if err := os.Chmod(filepath.Join(dir, "config.json"), 0o644); err != nil {
				t.Fatal(err)
			}
			return privateKey.PublicKey().String()
		}},
		{name: "config owner executable", setup: func(t *testing.T, dir string) string {
			writeTestConfigWithKey(t, dir, privateKey)
			if err := os.Chmod(filepath.Join(dir, "config.json"), 0o700); err != nil {
				t.Fatal(err)
			}
			return privateKey.PublicKey().String()
		}},
		{name: "invalid private key", setup: func(t *testing.T, dir string) string {
			data, _ := json.Marshal(map[string]string{"PrivateKey": "not-a-key"})
			writeFile(t, filepath.Join(dir, "config.json"), data, 0o600)
			return privateKey.PublicKey().String()
		}},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name  string
			setup func(t *testing.T, dir string) string
		}{name: "config symlink", setup: func(t *testing.T, dir string) string {
			target := filepath.Join(t.TempDir(), "target.json")
			data, _ := json.Marshal(map[string]string{"PrivateKey": privateKey.String()})
			writeFile(t, target, data, 0o600)
			if err := os.Symlink(target, filepath.Join(dir, "config.json")); err != nil {
				t.Fatal(err)
			}
			return privateKey.PublicKey().String()
		}})
	}
	tests = append(tests, struct {
		name  string
		setup func(t *testing.T, dir string) string
	}{name: "wrong owner", setup: func(t *testing.T, dir string) string {
		writeTestConfigWithKey(t, dir, privateKey)
		return privateKey.PublicKey().String()
	}})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := secureTempDir(t)
			expected := tt.setup(t, dir)
			expectedUID := os.Geteuid()
			expectedGID := os.Getegid()
			if tt.name == "wrong owner" {
				expectedUID++
			}
			if _, err := LoadPersistentIdentity(dir, expected, expectedUID, expectedGID); err == nil {
				t.Fatal("LoadPersistentIdentity() error = nil")
			}
		})
	}
}

func TestLoadPersistentVolumeIdentityRequiresCompleteFinal(t *testing.T) {
	root, candidate := testCandidate(t, PhaseVerified, true)
	final := filepath.Join(root, finalStateDirName)
	if err := os.Rename(candidate, final); err != nil {
		t.Fatal(err)
	}
	j, err := ReadBootstrapJournal(final)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := LoadPersistentVolumeIdentity(root, j.PublicKey, os.Geteuid(), os.Getegid())
	if err != nil || identity.PublicKey != j.PublicKey {
		t.Fatalf("LoadPersistentVolumeIdentity() = %#v, %v", identity, err)
	}
	if err := os.Mkdir(filepath.Join(root, ".bootstrap-conflict"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPersistentVolumeIdentity(root, j.PublicKey, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("conflicting candidate was accepted")
	}
}

func writeTestConfig(t *testing.T, dir string) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeTestConfigWithKey(t, dir, key)
	return key
}

func writeTestConfigWithKey(t *testing.T, dir string, key wgtypes.Key) {
	t.Helper()
	data, err := json.Marshal(map[string]string{"PrivateKey": key.String()})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "config.json"), data, 0o600)
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
