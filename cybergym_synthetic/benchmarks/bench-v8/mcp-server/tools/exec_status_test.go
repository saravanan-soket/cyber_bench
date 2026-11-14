package tools

import (
	"os"
	"testing"
)

func TestRealUIDFromStatus(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   uint32
		ok     bool
	}{
		{
			name:   "typical",
			status: "Name:\tcat\nState:\tR (running)\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
			want:   1000, ok: true,
		},
		{
			name:   "root",
			status: "Name:\tinit\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
			want:   0, ok: true,
		},
		{
			// Real UID differs from effective: we must take the FIRST field.
			name:   "real differs from effective",
			status: "Name:\tx\nUid:\t1000\t0\t0\t1000\n",
			want:   1000, ok: true,
		},
		{
			// comm forged a "Uid:\t0..." line (appears just after Name, above
			// the real one). Scanning from the end must return the real UID.
			name:   "forged uid via comm is ignored",
			status: "Name:\t\nUid:\t0\t0\t0\t0\nUmask:\t0022\nState:\tR\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
			want:   1000, ok: true,
		},
		{
			name:   "no trailing newline",
			status: "State:\tS\nUid:\t7\t7\t7\t7",
			want:   7, ok: true,
		},
		{
			// A line that merely ends in "Uid:" must not match.
			name:   "lookalike prefix is not matched",
			status: "NStgid:\t1\nSomeUid:\t5\t5\t5\t5\nUid:\t9\t9\t9\t9\n",
			want:   9, ok: true,
		},
		{name: "missing uid line", status: "Name:\tx\nGid:\t1\t1\t1\t1\n", ok: false},
		{name: "non-numeric", status: "Uid:\tabc\tabc\n", ok: false},
		{name: "empty value", status: "Uid:\n", ok: false},
		{name: "empty input", status: "", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := realUIDFromStatus([]byte(tc.status))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("uid = %d, want %d", got, tc.want)
			}
		})
	}
}

// Parses the live /proc/self/status and matches os.Getuid(), guarding against
// kernel format drift.
func TestRealUIDFromStatusMatchesSelf(t *testing.T) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("no /proc/self/status: %v", err)
	}
	got, ok := realUIDFromStatus(status)
	if !ok {
		t.Fatal("could not parse Uid from live /proc/self/status")
	}
	if want := uint32(os.Getuid()); got != want {
		t.Fatalf("parsed uid = %d, want %d", got, want)
	}
}
