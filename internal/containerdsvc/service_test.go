package containerdsvc

import "testing"

func TestIsExpectedVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{version: "2.4.2", want: true},
		{version: "v2.4.2+unknown", want: true},
		{version: "2.4.1", want: false},
		{version: "2.4.3", want: false},
		{version: "2.4.2-rc.1", want: false},
	} {
		if got := isExpectedVersion(tc.version); got != tc.want {
			t.Errorf("isExpectedVersion(%q) = %t, want %t", tc.version, got, tc.want)
		}
	}
}

func TestVersionOutputMatchesExactProgramAndVersionFields(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"containerd", "containerd github.com/containerd/containerd 2.4.2+unknown", true},
		{"ctr", "ctr github.com/containerd/containerd 2.4.2+unknown", true},
		{"containerd", "other github.com/containerd/containerd 2.4.2", false},
		{"ctr", "ctr github.com/containerd/containerd 2.4.3 (built for 2.4.2)", false},
	} {
		if got := versionOutputMatches(tc.output, tc.name); got != tc.want {
			t.Errorf("versionOutputMatches(%q, %q) = %t, want %t", tc.output, tc.name, got, tc.want)
		}
	}
}
