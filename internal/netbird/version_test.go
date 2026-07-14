package netbird

import (
	"testing"

	nbversion "github.com/netbirdio/netbird/version"
)

// TestLinknameTargetsNetbirdVersion guards the linkname only: if a netbird
// upgrade renames or moves the unexported `version` var, this fails loudly
// instead of silently falling back to "development" in production.
//
// We can't assert that init() actually populated a version from build info,
// because `go test` binaries strip the module dep list (info.Deps is empty);
// the production binary built with `go build` is what surfaces real deps.
func TestLinknameTargetsNetbirdVersion(t *testing.T) {
	original := netbirdVersion
	t.Cleanup(func() { netbirdVersion = original })

	const sentinel = "railbird-linkname-probe"
	netbirdVersion = sentinel
	if got := nbversion.NetbirdVersion(); got != sentinel {
		t.Fatalf("NetbirdVersion() = %q, want %q (linkname into netbird's version var is broken)", got, sentinel)
	}
}
