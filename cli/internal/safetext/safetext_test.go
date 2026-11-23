package safetext

import "testing"

func TestClean(t *testing.T) {
	cases := map[string]string{
		"web-01":                         "web-01",
		"x\nHost *\n  ProxyCommand evil": "x Host *   ProxyCommand evil",
		"red\x1b[31m":                    "red [31m",
		"tab\there":                      "tab here",
		"c1\u009bx":                      "c1 x",
		"rtl\u202eabc":                   "rtlabc",
		"Zürich":                         "Zürich",
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanAll(t *testing.T) {
	type inner struct{ Name string }
	v := struct {
		Name   string
		List   []string
		Nested []inner
		Map    map[string][]string
		Any    any
		Ptr    *inner
		hidden string
	}{
		Name:   "a\nb",
		List:   []string{"c\rd"},
		Nested: []inner{{Name: "e\x1bf"}},
		Map:    map[string][]string{"k\ney": {"v\nal"}},
		Any:    "g\nh",
		Ptr:    &inner{Name: "i\nj"},
		hidden: "k\nl",
	}
	CleanAll(&v)
	if v.Name != "a b" || v.List[0] != "c d" || v.Nested[0].Name != "e f" || v.Any != "g h" || v.Ptr.Name != "i j" {
		t.Fatalf("not cleaned: %+v", v)
	}
	if got, ok := v.Map["k ey"]; !ok || got[0] != "v al" || len(v.Map) != 1 {
		t.Fatalf("map not cleaned: %v", v.Map)
	}
	if v.hidden != "k\nl" {
		t.Fatal("unexported fields are left alone")
	}
}
