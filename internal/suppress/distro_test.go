package suppress

import (
	"os"
	"testing"
)

func writeTmpOSRelease(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "os-release")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestParseOSRelease(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "ubuntu",
			content: "ID=ubuntu\nID_LIKE=debian\n",
			want:    "ubuntu",
		},
		{
			name:    "rhel",
			content: "ID=rhel\nID_LIKE=\"fedora\"\n",
			want:    "rhel",
		},
		{
			name:    "oracle linux maps to rhel",
			content: "ID=\"ol\"\nID_LIKE=\"rhel fedora\"\n",
			want:    "rhel",
		},
		{
			name:    "debian",
			content: "ID=debian\n",
			want:    "debian",
		},
		{
			name:    "debian-derived (raspbian)",
			content: "ID=raspbian\nID_LIKE=debian\n",
			want:    "debian",
		},
		{
			name:    "unknown distro",
			content: "ID=alpine\n",
			want:    "",
		},
		{
			name:    "empty file",
			content: "",
			want:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTmpOSRelease(t, tc.content)
			if got := parseOSRelease(path); got != tc.want {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestParseOSRelease_MissingFile(t *testing.T) {
	if got := parseOSRelease("/nonexistent/os-release"); got != "" {
		t.Errorf("want empty string for missing file, got %q", got)
	}
}
