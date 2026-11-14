package redact

import "testing"

func TestMessageRedactsSecrets(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Failed password for root from 10.0.0.9", "Failed password for root from 10.0.0.9"}, // "password for" is not key=value
		{"login password=hunter2 ok", "login password=" + Placeholder + " ok"},
		{"api_key = AKIA123SECRET done", "api_key = " + Placeholder + " done"},
		{"token: abc.def.ghi", "token: " + Placeholder},
		{`connecting to mongodb://user:p4ss@blue/syslog`, "connecting to mongodb://" + Placeholder + "@blue/syslog"},
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9", "Authorization: Bearer " + Placeholder},
		{`{"level":"info","password":"hunter2","user":"bob"}`, `{"level":"info","password":"REDACTED","user":"bob"}`},
		{"nothing secret here", "nothing secret here"},
	}
	for _, c := range cases {
		if got := Message(c.in); got != c.want {
			t.Errorf("Message(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

func TestMessageEmpty(t *testing.T) {
	if Message("") != "" {
		t.Error("empty in → empty out")
	}
}
