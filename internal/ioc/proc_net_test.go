package ioc_test

import (
	"testing"

	"github.com/pathfinder/internal/ioc"
)

func TestParseProcNetIP_IPv4(t *testing.T) {
	// /proc/net stores the 4 IPv4 bytes in host (little-endian) order.
	// "0100007F" -> 127.0.0.1 ; "0565DCB9" -> 185.220.101.5
	cases := map[string]string{
		"0100007F": "127.0.0.1",
		"0565DCB9": "185.220.101.5",
	}
	for hexAddr, want := range cases {
		got := ioc.ParseProcNetIP(hexAddr)
		if got == nil || got.String() != want {
			t.Errorf("ParseProcNetIP(%q) = %v, want %s", hexAddr, got, want)
		}
	}
}

func TestParseProcNetIP_Invalid(t *testing.T) {
	for _, bad := range []string{"", "ZZ", "0100007", "local_address"} {
		if ip := ioc.ParseProcNetIP(bad); ip != nil {
			t.Errorf("ParseProcNetIP(%q) = %v, want nil", bad, ip)
		}
	}
}

func TestScanProcNetForIPs_MatchesRemoteAddr(t *testing.T) {
	sh := &ioc.IOCSet{}
	if err := ioc.AppendIPMatcher(sh, "185.220.101.5"); err != nil {
		t.Fatal(err)
	}
	// A realistic /proc/net/tcp body: header line + one data row whose
	// rem_address is 185.220.101.5:443 -> "0565DCB9:01BB".
	body := "  sl  local_address rem_address   st\n" +
		"   0: 0100007F:0035 0565DCB9:01BB 01\n"
	hits := ioc.ScanProcNetForIPs(body, sh)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if hits[0].Indicator != "185.220.101.5" {
		t.Errorf("indicator = %q, want 185.220.101.5", hits[0].Indicator)
	}
}
