package forward

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []Forward
		wantErr bool
	}{
		{"single host:port", "db.local:5432", []Forward{{ListenPort: "5432", Target: "db.local:5432"}}, false},
		{"lport=target", "5432=db.local:5432", []Forward{{ListenPort: "5432", Target: "db.local:5432"}}, false},
		{"multi with spaces", "5432=db.local:5432, 6379=cache:6379", []Forward{
			{ListenPort: "5432", Target: "db.local:5432"},
			{ListenPort: "6379", Target: "cache:6379"},
		}, false},
		{"empty input", "", nil, true},
		{"missing port in target", "5432=nohostport", nil, true},
		{"missing port in single", "nohostport", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr=%v", err, c.wantErr)
			}
			if c.wantErr {
				return
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
