// Package safetext makes text from the server safe to print and to write into config files:
// a name with a line break or a terminal escape sequence must not become a new ssh_config line
// or repaint the person's terminal.
package safetext

import (
	"reflect"
	"strings"
	"unicode"
)

// bidi reports the Unicode bidirectional controls, which can make text read differently from
// what it is.
func bidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F
}

// Has reports whether s holds a control character or a bidirectional control.
func Has(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || bidi(r) }) >= 0
}

// Clean replaces control characters (line breaks, ESC, C1 controls) with a space and drops
// bidirectional controls.
func Clean(s string) string {
	if !Has(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch {
		case bidi(r):
			return -1
		case unicode.IsControl(r):
			return ' '
		}
		return r
	}, s)
}

// CleanAll runs Clean on every string reachable from v (a pointer to decoded JSON): struct
// fields, slices, map keys and values.
func CleanAll(v any) {
	if v == nil {
		return
	}
	clean(reflect.ValueOf(v))
}

func clean(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			clean(v.Elem())
		}
	case reflect.Interface:
		if v.IsNil() || !v.CanSet() {
			return
		}
		inner := reflect.New(v.Elem().Type()).Elem()
		inner.Set(v.Elem())
		clean(inner)
		v.Set(inner)
	case reflect.String:
		if v.CanSet() {
			if s := v.String(); Has(s) {
				v.SetString(Clean(s))
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				clean(f)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			clean(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		for _, key := range v.MapKeys() {
			value := reflect.New(v.Type().Elem()).Elem()
			value.Set(v.MapIndex(key))
			clean(value)
			newKey := key
			if key.Kind() == reflect.String && Has(key.String()) {
				newKey = reflect.ValueOf(Clean(key.String())).Convert(key.Type())
				v.SetMapIndex(key, reflect.Value{})
			}
			v.SetMapIndex(newKey, value)
		}
	}
}
