// Package dns turns systemd-resolved query-monitor messages (the output of
// `resolvectl monitor --json=short`, i.e. the parameters of
// io.systemd.Resolve.Monitor.SubscribeQueryResults replies) into Mongo
// documents, one per completed lookup.
//
// Each message looks like
//
//	{"state":"success","question":[{"class":1,"type":1,"name":"example.com"}],
//	 "answer":[{"rr":{"key":{...},"address":[93,184,215,14]},"raw":"<base64 RR>","ifindex":2}]}
//
// with "rcode" present on state "rcode-failure" and "errno" on "errno".
// Answer records are decoded from the wire-format "raw" field when present
// (stable across systemd versions) and from the "rr" JSON otherwise.
package dns

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"mongo-journald/internal/model"
)

// Build maps one monitor message to a document. ok is false for messages
// that are not query results (e.g. a "ready" notification).
func Build(msg map[string]any, server string, now time.Time, retention time.Duration) (model.Doc, bool) {
	q := firstQuestion(msg)
	if q == nil {
		return nil, false
	}
	state, _ := msg["state"].(string)
	doc := model.Doc{
		"at":     now.UTC(),
		"server": server,
		"qname":  NormName(str(q, "name")),
		"qtype":  typeName(num(q, "type")),
		"state":  state,
	}
	if rc, ok := rcode(msg, state); ok {
		doc["rcode"] = rc
	}
	if e, ok := msg["errno"]; ok {
		if n, ok := toInt(e); ok {
			doc["errno"] = n
		}
	}
	if ede, ok := toInt(msg["extendedDNSErrorCode"]); ok {
		doc["ede"] = ede
		if s, _ := msg["extendedDNSErrorMessage"].(string); s != "" {
			doc["edeMsg"] = s
		}
	}
	if answers := Answers(msg["answer"]); len(answers) > 0 {
		for _, a := range answers {
			if a["type"] == "CNAME" && doc["cname"] == nil {
				doc["cname"] = a["data"]
			}
		}
		doc["answers"] = answers
	}
	if retention > 0 {
		doc["expireAt"] = doc["at"].(time.Time).Add(retention)
	}
	return doc, true
}

// NormName lowercases a DNS name and drops the trailing root dot.
func NormName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 1 {
		s = strings.TrimSuffix(s, ".")
	}
	return s
}

func firstQuestion(msg map[string]any) map[string]any {
	for _, k := range []string{"question", "collectedQuestions"} {
		if arr, ok := msg[k].([]any); ok && len(arr) > 0 {
			if q, ok := arr[0].(map[string]any); ok {
				return q
			}
		}
	}
	return nil
}

// rcode names the result: NOERROR for success, the server's rcode on
// rcode-failure. Other states (timeout, no-servers, errno, …) carry no
// rcode; the state field says what happened.
func rcode(msg map[string]any, state string) (string, bool) {
	if n, ok := toInt(msg["rcode"]); ok {
		return RCodeName(n), true
	}
	if state == "success" {
		return "NOERROR", true
	}
	return "", false
}

var rcodes = [...]string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
	"YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI"}

// RCodeName returns the IANA mnemonic for a DNS rcode, or "RCODE<n>".
func RCodeName(n int) string {
	if n >= 0 && n < len(rcodes) {
		return rcodes[n]
	}
	if n == 16 {
		return "BADVERS"
	}
	return "RCODE" + strconv.Itoa(n)
}

// Answers decodes the answer array.
func Answers(v any) []model.Doc {
	arr, _ := v.([]any)
	var out []model.Doc
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if raw, _ := m["raw"].(string); raw != "" {
			if a, ok := fromRaw(raw); ok {
				out = append(out, a)
				continue
			}
		}
		if rr, ok := m["rr"].(map[string]any); ok {
			if a, ok := fromJSON(rr); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// fromRaw parses one wire-format RR by wrapping it in a single-answer
// message.
func fromRaw(b64 string) (model.Doc, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	msg := make([]byte, 12, 12+len(raw))
	binary.BigEndian.PutUint16(msg[6:], 1) // ANCOUNT
	msg = append(msg, raw...)
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, false
	}
	h, err := p.AnswerHeader()
	if err != nil {
		return nil, false
	}
	a := model.Doc{"name": NormName(h.Name.String()), "type": typeName(int(h.Type)), "ttl": int64(h.TTL)}
	switch h.Type {
	case dnsmessage.TypeA:
		r, err := p.AResource()
		if err != nil {
			return nil, false
		}
		a["data"] = netip.AddrFrom4(r.A).String()
	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		if err != nil {
			return nil, false
		}
		a["data"] = netip.AddrFrom16(r.AAAA).String()
	case dnsmessage.TypeCNAME:
		r, err := p.CNAMEResource()
		if err != nil {
			return nil, false
		}
		a["data"] = NormName(r.CNAME.String())
	case dnsmessage.TypePTR:
		r, err := p.PTRResource()
		if err != nil {
			return nil, false
		}
		a["data"] = NormName(r.PTR.String())
	case dnsmessage.TypeNS:
		r, err := p.NSResource()
		if err != nil {
			return nil, false
		}
		a["data"] = NormName(r.NS.String())
	case dnsmessage.TypeMX:
		r, err := p.MXResource()
		if err != nil {
			return nil, false
		}
		a["data"] = strconv.Itoa(int(r.Pref)) + " " + NormName(r.MX.String())
	case dnsmessage.TypeSRV:
		r, err := p.SRVResource()
		if err != nil {
			return nil, false
		}
		a["data"] = fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, NormName(r.Target.String()))
	case dnsmessage.TypeTXT:
		r, err := p.TXTResource()
		if err != nil {
			return nil, false
		}
		a["data"] = strings.Join(r.TXT, "")
	case dnsmessage.TypeSOA:
		r, err := p.SOAResource()
		if err != nil {
			return nil, false
		}
		a["data"] = NormName(r.NS.String()) + " " + NormName(r.MBox.String())
	default:
		// keep name/type/ttl; the rdata of exotic types is not worth storing
	}
	return a, true
}

// fromJSON reads resolved's JSON RR form (key plus per-type fields).
func fromJSON(rr map[string]any) (model.Doc, bool) {
	key, _ := rr["key"].(map[string]any)
	if key == nil {
		return nil, false
	}
	a := model.Doc{"name": NormName(str(key, "name")), "type": typeName(num(key, "type"))}
	switch {
	case rr["address"] != nil:
		if s := addr(rr["address"]); s != "" {
			a["data"] = s
		}
	case rr["name"] != nil:
		name := NormName(str(rr, "name"))
		if p, ok := toInt(rr["priority"]); ok {
			if port, ok := toInt(rr["port"]); ok { // SRV
				w, _ := toInt(rr["weight"])
				a["data"] = fmt.Sprintf("%d %d %d %s", p, w, port, name)
			} else { // MX
				a["data"] = fmt.Sprintf("%d %s", p, name)
			}
		} else {
			a["data"] = name
		}
	case rr["items"] != nil:
		if items, ok := rr["items"].([]any); ok {
			var parts []string
			for _, it := range items {
				if s, ok := it.(string); ok {
					parts = append(parts, s)
				}
			}
			a["data"] = strings.Join(parts, "")
		}
	}
	return a, true
}

// addr accepts an address as a byte array ([93,184,215,14]) or a string.
func addr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		b := make([]byte, 0, len(x))
		for _, e := range x {
			n, ok := toInt(e)
			if !ok || n < 0 || n > 255 {
				return ""
			}
			b = append(b, byte(n))
		}
		if a, ok := netip.AddrFromSlice(b); ok {
			return a.String()
		}
	}
	return ""
}

func typeName(t int) string {
	if t <= 0 {
		return ""
	}
	s := dnsmessage.Type(t).String()
	if n, ok := strings.CutPrefix(s, "Type"); ok {
		return n
	}
	return "TYPE" + strconv.Itoa(t) // unknown types render as a bare number
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func num(m map[string]any, k string) int {
	n, _ := toInt(m[k])
	return n
}

func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	case string:
		n, err := strconv.Atoi(x)
		return n, err == nil
	}
	return 0, false
}
