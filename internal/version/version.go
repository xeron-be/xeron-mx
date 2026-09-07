package version

import "runtime/debug"

var (
	Version = "dev"

	Commit = "unknown"

	Date = "unknown"
)

func String() string {
	return Version + " (" + Commit + ", built " + Date + ")"
}

func init() {

	if Commit != "unknown" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 7 {
				Commit = s.Value[:7]
			}
		case "vcs.time":
			Date = s.Value
		}
	}
}
