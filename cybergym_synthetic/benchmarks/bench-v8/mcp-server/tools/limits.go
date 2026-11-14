package tools

import "fmt"

// truncateBytes caps s to max bytes. If s is longer, the excess is
// replaced with a marker reporting the original byte count so callers
// (and downstream agents) know data was dropped and can ask for more
// (e.g. via grade's verbose flag, or a narrower exec/read_file query).
func truncateBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n... [truncated, %d bytes total]", len(s))
}
