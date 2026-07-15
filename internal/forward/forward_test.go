package forward

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []Forward
		wantErr string
	}{
		{"single host:port", "db.local:5432", []Forward{{ListenPort: "5432", Target: "db.local:5432"}}, ""},
		{"lport=target", "5432=db.local:5432", []Forward{{ListenPort: "5432", Target: "db.local:5432"}}, ""},
		{"multi with spaces", "5432=db.local:5432, 6379=cache:6379", []Forward{
			{ListenPort: "5432", Target: "db.local:5432"},
			{ListenPort: "6379", Target: "cache:6379"},
		}, ""},
		{"ipv6 target", "443=[2001:db8::1]:65535", []Forward{{ListenPort: "443", Target: "[2001:db8::1]:65535"}}, ""},
		{"minimum ports", "1=db.local:1", []Forward{{ListenPort: "1", Target: "db.local:1"}}, ""},
		{"maximum ports", "65535=db.local:65535", []Forward{{ListenPort: "65535", Target: "db.local:65535"}}, ""},
		{"ports normalized", "01=db.local:0001", []Forward{{ListenPort: "1", Target: "db.local:1"}}, ""},
		{"empty input", "", nil, "empty"},
		{"empty list item", "1=a:1,,2=b:2", nil, "entry 2 is empty"},
		{"empty listen port", "=db.local:1", nil, "listen port"},
		{"missing port in target", "5432=nohostport", nil, "invalid target"},
		{"empty target host", "5432=:5432", nil, "invalid target"},
		{"invalid target host", "5432=bad_host:5432", nil, "invalid target"},
		{"missing port in single", "nohostport", nil, "invalid target"},
		{"zero listen port", "0=db.local:1", nil, "listen port"},
		{"large listen port", "65536=db.local:1", nil, "listen port"},
		{"text listen port", "db=db.local:1", nil, "listen port"},
		{"zero target port", "1=db.local:0", nil, "target port"},
		{"large target port", "1=db.local:65536", nil, "target port"},
		{"text target port", "1=db.local:db", nil, "target port"},
		{"duplicate explicit listeners", "1=a:1,1=b:2", nil, "entries 1 and 2"},
		{"inferred explicit collision", "a:5432,5432=b:5432", nil, "entries 1 and 2"},
		{"secret-like target not reflected", "1=user:password@host", nil, "target port"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.in)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, c.wantErr)
				}
				if strings.Contains(err.Error(), "user:password") {
					t.Fatalf("error leaked target: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d (%+v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got[%d] = %+v want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}
