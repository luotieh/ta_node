// Package buildinfo exposes the binary's VCS build identity (embedded by the
// Go toolchain as vcs.* build settings) so the running version can be
// confirmed at runtime via the health API and the config page.
package buildinfo

import "runtime/debug"

type Info struct {
	Revision string `json:"revision"`
	Time     string `json:"time,omitempty"`
	Modified bool   `json:"modified"`
}

var resolved Info

func init() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			resolved.Revision = s.Value
		case "vcs.time":
			resolved.Time = s.Value
		case "vcs.modified":
			resolved.Modified = s.Value == "true"
		}
	}
}

// Get returns the build identity, with the revision shortened to 12 chars.
func Get() Info {
	out := resolved
	if len(out.Revision) > 12 {
		out.Revision = out.Revision[:12]
	}
	return out
}

// Short returns a compact version string: "<rev>", "<rev>-dirty", or "unknown"
// (when the binary was built outside a VCS checkout).
func Short() string {
	i := Get()
	if i.Revision == "" {
		return "unknown"
	}
	if i.Modified {
		return i.Revision + "-dirty"
	}
	return i.Revision
}
