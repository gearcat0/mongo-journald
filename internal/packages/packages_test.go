package packages

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const sample = "apt\tamd64\t3.2.1ubuntu0.1\tapt\tinstall\tinstalled\n" +
	"apt-utils\tamd64\t3.2.1ubuntu0.1\tapt\tinstall\tinstalled\n" +
	"libc6\ti386\t2.42-0ubuntu3\tglibc\tinstall\tinstalled\n" +
	"linux-image-generic\tamd64\t7.0.0-43.43\tlinux-meta\thold\tinstalled\n" +
	"oldthing\tall\t1.0-1\toldthing\tdeinstall\tconfig-files\n" +
	"gone\tamd64\t\tgone\tunknown\tnot-installed\n"

func TestParse(t *testing.T) {
	pkgs, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 5 {
		t.Fatalf("want 5 packages (not-installed skipped), got %d: %+v", len(pkgs), pkgs)
	}
	if got, want := pkgs[1], (Package{Name: "apt-utils", Arch: "amd64", Version: "3.2.1ubuntu0.1", Source: "apt", Status: "installed"}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if pkgs[2].Arch != "i386" || pkgs[2].Source != "glibc" {
		t.Errorf("libc6: %+v", pkgs[2])
	}
	if !pkgs[3].Hold || pkgs[0].Hold {
		t.Errorf("hold: %+v %+v", pkgs[3], pkgs[0])
	}
	if pkgs[4].Status != "config-files" {
		t.Errorf("status: %+v", pkgs[4])
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "apt amd64 3.2.1\n", "apt\tamd64\n", "gone\tamd64\t\tgone\tunknown\tnot-installed\n"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("want error for %q", bad)
		}
	}
}

func TestDoc(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	p := Package{Name: "apt", Arch: "amd64", Version: "3.2.1", Source: "apt", Status: "installed"}
	d := Doc(p, "dev", at, 14*24*time.Hour)
	if d["server"] != "dev" || d["name"] != "apt" || d["version"] != "3.2.1" || d["hold"] != false || d["at"] != at {
		t.Errorf("doc: %+v", d)
	}
	if d["expireAt"] != at.Add(14*24*time.Hour) {
		t.Errorf("expireAt: %v", d["expireAt"])
	}
	if _, ok := Doc(p, "dev", at, 0)["expireAt"]; ok {
		t.Error("retention 0 must not stamp expireAt")
	}
}

// TestListLive checks the real dpkg-query accepts the format string.
func TestListLive(t *testing.T) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("no dpkg-query")
	}
	pkgs, err := List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.Name == "" || p.Arch == "" || p.Status == "" || p.Source == "" {
			t.Fatalf("incomplete package: %+v", p)
		}
		if p.Status == "installed" && p.Version == "" {
			t.Fatalf("installed without version: %+v", p)
		}
	}
}
