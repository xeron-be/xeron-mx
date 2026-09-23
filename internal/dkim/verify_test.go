package dkim

import (
	"testing"
)

func TestCleanTXTRecord(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`"v=DKIM1; k=rsa; p=MIIBIj"`, `v=DKIM1; k=rsa; p=MIIBIj`},
		{`"v=DKIM1; k=rsa; " "p=MIIBIj"`, `v=DKIM1; k=rsa; p=MIIBIj`},
		{`v=DKIM1; k=rsa; p=MIIBIj`, `v=DKIM1; k=rsa; p=MIIBIj`},
	}
	for _, tc := range cases {
		got := CleanTXTRecord(tc.input)
		if got != tc.want {
			t.Errorf("CleanTXTRecord(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestExtractPublicKey(t *testing.T) {
	record := `v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA`
	want := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
	got := ExtractPublicKey(record)
	if got != want {
		t.Errorf("ExtractPublicKey() = %q, want %q", got, want)
	}

	recordWithSpaces := `v=DKIM1; k=rsa; p= MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA ; s=email`
	gotWithSpaces := ExtractPublicKey(recordWithSpaces)
	if gotWithSpaces != want {
		t.Errorf("ExtractPublicKey(with spaces) = %q, want %q", gotWithSpaces, want)
	}

	recordEmptyP := `v=DKIM1; k=rsa; p=`
	if ExtractPublicKey(recordEmptyP) != "" {
		t.Errorf("ExtractPublicKey(empty) = %q, want empty", ExtractPublicKey(recordEmptyP))
	}
}

func TestUniqueRecordsMergesTheSameRecordFromEveryResolver(t *testing.T) {
	google := "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7nYn"
	cloudflare := `"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0" "BAQEFAAOCAQ8AMIIBCgKCAQEA7nYn"`
	got := uniqueRecords([]string{google, cloudflare})
	if len(got) != 1 || got[0] != google {
		t.Fatalf("uniqueRecords = %q; want the one record once", got)
	}

	other := "v=DKIM1; k=rsa; p=OTHER"
	if got := uniqueRecords([]string{google, other, cloudflare}); len(got) != 2 {
		t.Fatalf("uniqueRecords = %q; want two distinct records", got)
	}
}
