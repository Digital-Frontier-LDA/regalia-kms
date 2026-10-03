// Package membership is deploy/baremetal/membership.py's accept() in Go, for the pre-root unlock client (#66, B3): the
// signed membership manifest chain, verified with the same rules, so the unlock client can take its peers
// from a manifest it checked rather than from a file anyone with the ESP could write.
//
// The rules and their order follow the Python exactly; tests/vectors/membership-v1.json, recorded from the
// Python tests, holds this package to them.
package membership

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// MaxBytes is the most a manifest or envelope may be (membership.MAX_BYTES).
const MaxBytes = 256 * 1024

// Load is membership.load: one JSON value, duplicate keys refused, no float (an integer is a json.Number
// with digits only), at most `limit` bytes. Objects become map[string]any, arrays []any.
func Load(raw []byte, limit int) (any, error) { return load(raw, limit, false) }

// load is Load; with floats (only for test fixtures that record what a document may NOT hold) a number with
// a fraction or an exponent is kept as a json.Number, which Validate then refuses as not an integer.
func load(raw []byte, limit int, floats bool) (any, error) {
	if len(raw) > limit {
		return nil, fmt.Errorf("a document is at most %d bytes here", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readValue(decoder, 0, floats)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("not valid JSON: extra data")
	}
	return value, nil
}

func readValue(decoder *json.Decoder, depth int, floats bool) (any, error) {
	if depth > 64 {
		return nil, errors.New("not valid JSON: nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %v", err)
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, fmt.Errorf("not valid JSON: %v", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("not valid JSON: a key is not a string")
				}
				if _, dup := object[key]; dup {
					return nil, fmt.Errorf("duplicate field %q", key)
				}
				value, err := readValue(decoder, depth+1, floats)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if _, err := decoder.Token(); err != nil {
				return nil, fmt.Errorf("not valid JSON: %v", err)
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				value, err := readValue(decoder, depth+1, floats)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, fmt.Errorf("not valid JSON: %v", err)
			}
			return array, nil
		}
		return nil, errors.New("not valid JSON")
	case json.Number:
		if strings.ContainsAny(string(t), ".eE") && !floats {
			return nil, fmt.Errorf("floats are not allowed (%s)", t)
		}
		return t, nil
	default:
		return t, nil // string, bool, nil
	}
}

// Canonical is membership.canonical: json.dumps(obj, sort_keys=True, separators=(",", ":"),
// ensure_ascii=True), byte for byte.
func Canonical(value any) []byte {
	var out bytes.Buffer
	canonical(&out, value)
	return out.Bytes()
}

func canonical(out *bytes.Buffer, value any) {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		// an integer: Python writes it in decimal, without leading zeros or a plus sign
		n, ok := new(bigInt).set(string(v))
		if !ok {
			out.WriteString(string(v))
			return
		}
		out.WriteString(n)
	case int:
		out.WriteString(strconv.Itoa(v))
	case string:
		quote(out, v)
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			canonical(out, item)
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return lessCodePoints(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			quote(out, key)
			out.WriteByte(':')
			canonical(out, v[key])
		}
		out.WriteByte('}')
	default:
		panic(fmt.Sprintf("membership: cannot write %T canonically", value))
	}
}

// lessCodePoints orders as Python's sorted() orders str keys: by code point.
func lessCodePoints(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

// quote is Python's json string encoding with ensure_ascii=True.
func quote(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r >= 0x7f && r < 0x10000): // everything outside " " to "~" (Python's ESCAPE_ASCII)
				fmt.Fprintf(out, `\u%04x`, r)
			case r >= 0x10000:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(out, `\u%04x\u%04x`, hi, lo)
			default:
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// bigInt writes a JSON integer as Python would: no leading zeros, "-0" as "0".
type bigInt struct{}

func (bigInt) set(text string) (string, bool) {
	negative := strings.HasPrefix(text, "-")
	digits := strings.TrimPrefix(text, "-")
	if digits == "" {
		return "", false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0", true
	}
	if negative {
		return "-" + digits, true
	}
	return digits, true
}
