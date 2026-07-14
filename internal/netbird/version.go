package netbird

import (
	"runtime/debug"
	"strings"
	_ "unsafe" // required for go:linkname
)

// netbirdVersion aliases the unexported `version` variable in
// github.com/netbirdio/netbird/version. Upstream sets that string via
// goreleaser's `-ldflags -X` when they cut a release; when we vendor netbird
// as a library, nothing rewrites it and it stays at the source default
// ("development"). The NetBird management server forwards that string to the
// dashboard, which then offers an update because "development" sorts below
// every real release.
//
// Reading the resolved netbird module version from our binary's own build
// info and writing it through this alias keeps go.mod as the single source of
// truth: bumping the require line in go.mod is enough.
//
//go:linkname netbirdVersion github.com/netbirdio/netbird/version.version
var netbirdVersion string

const netbirdModulePath = "github.com/netbirdio/netbird"

func init() {
	if v := moduleVersion(netbirdModulePath); v != "" {
		netbirdVersion = v
	}
}

// moduleVersion returns the resolved version string (without the leading "v")
// for the given module path, or "" if the binary has no usable build info or
// the module is not in the dependency graph.
func moduleVersion(path string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range info.Deps {
		if dep == nil || dep.Path != path {
			continue
		}
		// A `replace` directive points at a different module; that
		// module's Version is what actually got compiled in.
		if dep.Replace != nil && dep.Replace.Version != "" {
			return strings.TrimPrefix(dep.Replace.Version, "v")
		}
		return strings.TrimPrefix(dep.Version, "v")
	}
	return ""
}
