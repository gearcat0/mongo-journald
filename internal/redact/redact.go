// Package redact scrubs likely secrets from a log message before it is
// shipped. It is conservative: it rewrites only recognised secret
// key=value / "key: value" pairs, URL credentials, bearer/basic tokens,
// and secret keys inside a whole-line JSON object — ordinary log text is
// left untouched. Modelled on the mover's obs.redact, narrowed to free
// text.
package redact

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Placeholder replaces a redacted value.
const Placeholder = "REDACTED"

// secretKeys are field/parameter names whose value is a credential
// (matched case-insensitively), in key=value pairs and JSON objects.
var secretKeys = []string{
	"password", "passwd", "pwd", "passphrase",
	"secret", "secretkey", "secret_key",
	"apikey", "api_key", "accesskey", "access_key", "accesskeyid",
	"access_token", "accesstoken", "auth_token", "authtoken",
	"token", "authorization", "sign", "signature",
	"session", "sessionid", "session_id", "cookie",
	"private_key", "privatekey",
}

var secretKeySet = func() map[string]bool {
	m := make(map[string]bool, len(secretKeys))
	for _, k := range secretKeys {
		m[k] = true
	}
	return m
}()

func isSecretKey(k string) bool { return secretKeySet[strings.ToLower(k)] }

var (
	kvRe    = buildKVRegexp()
	urlRe   = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+@`)
	tokenRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
)

// buildKVRegexp matches a secret key, a ':' or '=' separator (with
// optional spaces), and its value (a quoted string or a non-space run).
// Keys are tried longest-first so access_key wins over accesskey.
func buildKVRegexp() *regexp.Regexp {
	ks := append([]string(nil), secretKeys...)
	sort.Slice(ks, func(i, j int) bool { return len(ks[i]) > len(ks[j]) })
	for i, k := range ks {
		ks[i] = regexp.QuoteMeta(k)
	}
	return regexp.MustCompile(`(?i)\b(` + strings.Join(ks, "|") + `)(\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`)
}

// Message returns s with likely secrets replaced by the placeholder.
func Message(s string) string {
	if s == "" {
		return s
	}
	// A whole-line JSON object (common for apps that log structured JSON):
	// redact secret keys structurally and re-emit.
	if t := strings.TrimSpace(s); strings.HasPrefix(t, "{") && json.Valid([]byte(t)) {
		var v any
		if json.Unmarshal([]byte(t), &v) == nil && redactJSON(v) {
			if out, err := json.Marshal(v); err == nil {
				return string(out)
			}
		}
	}
	// Bearer/Basic tokens first, so "authorization: Bearer <jwt>" keeps the
	// scheme word and redacts the token, rather than the kv pass eating only
	// "Bearer" and leaving the token.
	s = tokenRe.ReplaceAllString(s, `$1 `+Placeholder)
	s = urlRe.ReplaceAllString(s, `${1}`+Placeholder+"@")
	s = kvRe.ReplaceAllStringFunc(s, func(m string) string {
		g := kvRe.FindStringSubmatch(m) // [full, key, sep, value]
		switch strings.ToLower(strings.Trim(g[3], `"'`)) {
		case "bearer", "basic", "digest", "negotiate", strings.ToLower(Placeholder):
			return m // scheme word (its token is handled above) or already redacted
		}
		return g[1] + g[2] + Placeholder
	})
	return s
}

func redactJSON(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if isSecretKey(k) {
				t[k] = Placeholder
				changed = true
			} else if redactJSON(x) {
				changed = true
			}
		}
	case []any:
		for _, x := range t {
			if redactJSON(x) {
				changed = true
			}
		}
	}
	return changed
}
