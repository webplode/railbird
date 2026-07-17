package config

import (
	"reflect"
	"strings"
	"testing"
)

func mapGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad(t *testing.T) {
	required := map[string]string{
		"FORWARDS":          "5432=db:5432",
		"NB_MANAGEMENT_URL": "https://mgmt",
		"NB_SETUP_KEY":      "key",
	}

	cases := []struct {
		name    string
		args    []string
		env     map[string]string
		want    Config
		wantErr string
	}{
		{
			name: "all from env, defaults filled",
			env:  required,
			want: Config{
				Forwards: "5432=db:5432", Mode: ModeIngress,
				ManagementURL: "https://mgmt", SetupKey: "key",
				DeviceName: "railbird", StateDir: "/var/lib/netbird", LogLevel: "info",
			},
		},
		{
			name: "TARGET_ADDR alias used when FORWARDS missing",
			env: map[string]string{
				"TARGET_ADDR": "5432=db:5432", "NB_MANAGEMENT_URL": "https://mgmt", "NB_SETUP_KEY": "key",
			},
			want: Config{
				Forwards: "5432=db:5432", Mode: ModeIngress,
				ManagementURL: "https://mgmt", SetupKey: "key",
				DeviceName: "railbird", StateDir: "/var/lib/netbird", LogLevel: "info",
			},
		},
		{
			name: "FORWARDS wins over TARGET_ADDR",
			env: map[string]string{
				"FORWARDS": "1=a:1", "TARGET_ADDR": "2=b:2",
				"NB_MANAGEMENT_URL": "https://mgmt", "NB_SETUP_KEY": "key",
			},
			want: Config{
				Forwards: "1=a:1", Mode: ModeIngress,
				ManagementURL: "https://mgmt", SetupKey: "key",
				DeviceName: "railbird", StateDir: "/var/lib/netbird", LogLevel: "info",
			},
		},
		{
			name: "explicit flag overrides env",
			args: []string{"--mode=egress", "--device-name=custom"},
			env:  required,
			want: Config{
				Forwards: "5432=db:5432", Mode: ModeEgress,
				ManagementURL: "https://mgmt", SetupKey: "key",
				DeviceName: "custom", StateDir: "/var/lib/netbird", LogLevel: "info",
			},
		},
		{
			name: "dns labels split and trimmed",
			env: mergeEnv(required, map[string]string{
				"NB_DNS_LABELS": " a , ,b,c ",
			}),
			want: Config{
				Forwards: "5432=db:5432", Mode: ModeIngress,
				ManagementURL: "https://mgmt", SetupKey: "key",
				DeviceName: "railbird", DNSLabels: []string{"a", "b", "c"},
				StateDir: "/var/lib/netbird", LogLevel: "info",
			},
		},
		{
			name:    "missing forwards",
			env:     map[string]string{"NB_MANAGEMENT_URL": "https://mgmt", "NB_SETUP_KEY": "key"},
			wantErr: "--forwards",
		},
		{
			name:    "missing mgmt",
			env:     map[string]string{"FORWARDS": "1=a:1", "NB_SETUP_KEY": "key"},
			wantErr: "--mgmt",
		},
		{
			name:    "missing setup-key",
			env:     map[string]string{"FORWARDS": "1=a:1", "NB_MANAGEMENT_URL": "https://mgmt"},
			wantErr: "--setup-key",
		},
		{
			name:    "invalid mode",
			args:    []string{"--mode=sideways"},
			env:     required,
			wantErr: "invalid mode",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Load(c.args, mapGetenv(c.env))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("config mismatch:\n got=%+v\nwant=%+v", got, c.want)
			}
		})
	}
}

func mergeEnv(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
