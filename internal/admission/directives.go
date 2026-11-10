package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
	"golang.org/x/sys/unix"
)

// THE SURVIVOR'S DIRECTIVES (regalia-j18; owner packet item 212: refuse every key a directive disabled, and every
// key when the store cannot be read). deploy/baremetal/survivor.py's Directives keeps the owner's signed disable
// directives, one canonical line each, in DirectivesPath (regalia-kds: on the disk, so a reboot does not empty
// them). ReadDisabled is Directives.held() and disabled(): the same file and directory checks and the same line
// validation, so the daemon refuses exactly the keys the survivor applied. Any doubt about the file refuses EVERY
// key; it never reads as "nothing disabled". tests/vectors/survivor-directives-v1.json holds the two to one rule.

// DirectivesPath is survivor.STORE_DIR/survivor.DIRECTIVES_FILE.
const DirectivesPath = "/var/lib/regalia-survivor/survivor-directives.jsonl"

const (
	// MaxDirectivesBytes is survivor.MAX_DIRECTIVES_BYTES.
	MaxDirectivesBytes = 4 * 1024 * 1024
	directiveSchema    = "regalia.survivor-directive/v1"
	maxReasonBytes     = 512 // survivor.MAX_FENCED_BYTES, the bound on a directive's reason
)

var (
	directiveKeys = []string{"schema", "object_id", "state", "quarantine_epoch", "quarantine_digest", "issued_at", "reason"}
	utcPattern    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	epochPattern  = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// errEveryKey ends each reason ReadDisabled gives: what the daemon does with it.
const errEveryKey = ": every key is refused"

// ReadDisabled is the set of object IDs the survivor's directives disable. ownerUID is who writes the store (root).
// A store that is not there yet is no directive (survivor.py: a missing file is []); a directory that is not there,
// or any check that fails, is an error, and the caller then refuses every key.
func ReadDisabled(path string, ownerUID uint32) (map[string]bool, error) {
	raw, err := readDirectives(path, ownerUID)
	if err != nil {
		return nil, err
	}
	disabled := map[string]bool{}
	for i, line := range splitLines(raw) {
		objectID, err := directiveObject(line)
		if err != nil {
			return nil, fmt.Errorf("the directives file is corrupt at line %d (%v)%s", i+1, err, errEveryKey)
		}
		disabled[objectID] = true
	}
	return disabled, nil
}

// readDirectives is Directives._directory, _open and _root_s: the directory opened without following a link, owned
// by ownerUID and closed to group and others (0700); the file opened relative to it, without following a link, a
// regular file of ownerUID's that only it may write, with one link.
func readDirectives(path string, ownerUID uint32) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("the directives path must be absolute and clean" + errEveryKey)
	}
	directory := filepath.Dir(path)
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("the directives directory %s cannot be opened (%v)%s", directory, err, errEveryKey)
	}
	defer unix.Close(dirFD)
	var dirStat unix.Stat_t
	if err := unix.Fstat(dirFD, &dirStat); err != nil || dirStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		dirStat.Uid != ownerUID || dirStat.Mode&0o077 != 0 {
		return nil, fmt.Errorf("%s is not a directory of root's that only root may enter (0700)%s", directory, errEveryKey)
	}
	fd, err := unix.Openat(dirFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the directives file cannot be opened (%v)%s", err, errEveryKey)
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != ownerUID ||
		stat.Mode&0o022 != 0 || stat.Nlink != 1 {
		return nil, fmt.Errorf("%s is not a regular, singly linked file of root's that only root may write%s", path, errEveryKey)
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxDirectivesBytes+1))
	if err != nil {
		return nil, fmt.Errorf("the directives file cannot be read%s", errEveryKey)
	}
	if len(raw) > MaxDirectivesBytes {
		return nil, errors.New("the directives file is oversized" + errEveryKey)
	}
	return raw, nil
}

// splitLines is Python's bytes.splitlines(): lines end at "\r\n", "\r" or "\n", and a separator at the very end
// starts no further line.
func splitLines(raw []byte) [][]byte {
	var lines [][]byte
	for len(raw) > 0 {
		end := bytes.IndexAny(raw, "\r\n")
		if end < 0 {
			return append(lines, raw)
		}
		lines = append(lines, raw[:end])
		if raw[end] == '\r' && end+1 < len(raw) && raw[end+1] == '\n' {
			end++
		}
		raw = raw[end+1:]
	}
	return lines
}

// directiveObject is one line of the store as Directives.held() takes it (membership.load, then exactly
// {"directive", "signature"}, then survivor.validate_directive): the object ID it disables. The signature is not
// verified here, as it is not there: survivor.py verifies a directive before it ever writes one.
func directiveObject(line []byte) (string, error) {
	value, err := membership.Load(line, membership.MaxBytes)
	if err != nil {
		return "", err
	}
	signed, err := exactKeys(value, []string{"directive", "signature"}, "a signed directive")
	if err != nil {
		return "", err
	}
	directive, err := exactKeys(signed["directive"], directiveKeys, "the survivor directive")
	if err != nil {
		return "", err
	}
	if directive["schema"] != directiveSchema {
		return "", errors.New("schema must be " + directiveSchema)
	}
	objectID, ok := directive["object_id"].(string)
	if !ok || !isName(objectID) {
		return "", errors.New("object_id must be a name")
	}
	if directive["state"] != "disabled" {
		return "", errors.New("a directive only disables")
	}
	if epoch, ok := directive["quarantine_epoch"].(json.Number); !ok || !epochPattern.MatchString(string(epoch)) {
		return "", errors.New("the directive's quarantine_epoch must be an integer >= 1")
	}
	if digest, ok := directive["quarantine_digest"].(string); !ok || !lowerHex(digest, 64) {
		return "", errors.New("the directive's quarantine_digest must be 64 lowercase hex")
	}
	if issued, ok := directive["issued_at"].(string); !ok || !realUTC(issued) {
		return "", errors.New("issued_at must be a real UTC time, YYYY-MM-DDTHH:MM:SSZ")
	}
	if reason, ok := directive["reason"].(string); !ok || !printableText(reason, maxReasonBytes) {
		return "", fmt.Errorf("reason must be printable text of at most %d bytes", maxReasonBytes)
	}
	return objectID, nil
}

func exactKeys(value any, keys []string, label string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	if len(object) != len(keys) {
		return nil, fmt.Errorf("%s fields mismatch", label)
	}
	for _, key := range keys {
		if _, has := object[key]; !has {
			return nil, fmt.Errorf("%s fields mismatch", label)
		}
	}
	return object, nil
}

// isName is survivor.NAME: 1 to 256 printable ASCII characters, no space.
func isName(text string) bool {
	if len(text) < 1 || len(text) > 256 {
		return false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < 0x21 || text[i] > 0x7e {
			return false
		}
	}
	return true
}

func lowerHex(text string, n int) bool {
	if len(text) != n {
		return false
	}
	for i := 0; i < len(text); i++ {
		if !(text[i] >= '0' && text[i] <= '9' || text[i] >= 'a' && text[i] <= 'f') {
			return false
		}
	}
	return true
}

// realUTC is heartbeat.parse_time: exactly the form and a real date. time.Parse refuses what strptime does (second
// 60, hour 24, the 30th of February) but takes year 0, which strptime refuses.
func realUTC(text string) bool {
	if !utcPattern.MatchString(text) || strings.HasPrefix(text, "0000-") {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05Z", text)
	return err == nil
}

// printableText is survivor._text: printable (Python's str.isprintable: no "Other" or "Separator" character but the
// ASCII space, which is unicode.IsPrint), not only spaces, at most `limit` bytes of UTF-8.
func printableText(text string, limit int) bool {
	if len(text) > limit || strings.Trim(text, " ") == "" {
		return false
	}
	for _, r := range text {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
