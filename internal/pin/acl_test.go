package pin

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// systemd hands a credential to a service that runs as its own user as a file owned by root, mode
// 0400, with an ACL entry granting that user read. stat then reports 0440, because with an ACL the
// group bits are the mask. The daemon refused that file, and so could never read its PIN under the
// shipped unit (measured in CI, systemd 255: e2e/kms-hardened-serve.sh). These tests build that ACL
// and the ones that must still be refused.
//
// A filesystem without ACLs can only skip, and a skip is a pass; this variable makes it a failure
// wherever the ACL is known to be settable (CI sets it).
const expectACLGuardEnforced = "REGALIA_EXPECT_ACL_GUARD_ENFORCED"

const aclUndefinedID = 0xffffffff

type aclEntry struct {
	tag, permissions uint16
	id               uint32
}

// setACL writes entries as system.posix_acl_access. The kernel wants them in tag order with a mask
// whenever a named entry exists; the callers below keep to that.
func setACL(t *testing.T, path string, entries []aclEntry) {
	t.Helper()
	raw := binary.LittleEndian.AppendUint32(nil, aclVersion)
	for _, entry := range entries {
		raw = binary.LittleEndian.AppendUint16(raw, entry.tag)
		raw = binary.LittleEndian.AppendUint16(raw, entry.permissions)
		raw = binary.LittleEndian.AppendUint32(raw, entry.id)
	}
	err := unix.Setxattr(path, "system.posix_acl_access", raw, 0)
	if err == nil {
		return
	}
	if !errors.Is(err, unix.ENOTSUP) {
		t.Fatalf("fixture: cannot set the ACL on %s: %v", path, err)
	}
	if expected, _ := strconv.ParseBool(os.Getenv(expectACLGuardEnforced)); expected {
		t.Fatalf("%s is set but this filesystem takes no ACL: the guard that was expected to run did not", expectACLGuardEnforced)
	}
	t.Skipf("this filesystem takes no POSIX ACL; set %s=1 wherever it does, to require this test rather than skip it", expectACLGuardEnforced)
}

func TestACredentialWithSystemdsACLIsReadAndAnyWiderACLIsRefused(t *testing.T) {
	self := uint32(os.Geteuid())
	other := self + 1
	// owner r--, [named entries], owning group ---, [named groups], mask, other ---
	acl := func(mask uint16, users, groups []aclEntry, groupObj uint16) []aclEntry {
		entries := []aclEntry{{aclUserObj, aclRead, aclUndefinedID}}
		entries = append(entries, users...)
		entries = append(entries, aclEntry{aclGroupObj, groupObj, aclUndefinedID})
		entries = append(entries, groups...)
		return append(entries, aclEntry{aclMask, mask, aclUndefinedID}, aclEntry{aclOther, 0, aclUndefinedID})
	}
	cases := []struct {
		name     string
		entries  []aclEntry
		accepted bool
	}{
		{"systemd's: read for this process's user", acl(aclRead, []aclEntry{{aclUser, aclRead, self}}, nil, 0), true},
		{"an entry that grants another user nothing", acl(aclRead, []aclEntry{{aclUser, aclRead, self}, {aclUser, 0, other}}, nil, 0), true},
		{"read for another user", acl(aclRead, []aclEntry{{aclUser, aclRead, other}}, nil, 0), false},
		{"read for this user and another", acl(aclRead, []aclEntry{{aclUser, aclRead, self}, {aclUser, aclRead, other}}, nil, 0), false},
		{"write for this process's user", acl(6, []aclEntry{{aclUser, 6, self}}, nil, 0), false},
		{"read for a named group", acl(aclRead, []aclEntry{{aclUser, aclRead, self}}, []aclEntry{{aclGroup, aclRead, 12345}}, 0), false},
		{"read for the owning group", acl(aclRead, []aclEntry{{aclUser, aclRead, self}}, nil, aclRead), false},
	}
	directory := t.TempDir()
	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := writeCredential(t, directory, strconv.Itoa(index)+".pin", "123456", 0o400)
			setACL(t, path, testCase.entries)
			// The fixture must be the shape that tripped the old guard: group bits set by the mask.
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm()&0o070 == 0 {
				t.Fatalf("fixture: mode %04o after setting the ACL (err %v): the mask did not reach the group bits", info.Mode().Perm(), err)
			}
			source, err := NewLockedFileSource(map[string]string{"device": path})
			if err != nil {
				t.Fatal(err)
			}
			value, err := source.PIN(context.Background(), "device")
			if testCase.accepted {
				if err != nil || string(value) != "123456" {
					t.Fatalf("a credential only this process's user can read was refused: %v", err)
				}
				if err := source.Release(value); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || value != nil {
				t.Fatal("a credential someone else can use was accepted")
			}
		})
	}
}

// Without an ACL the mode is the whole answer, and a group bit is a group that can read the PIN.
func TestAGroupReadableCredentialWithNoACLIsStillRefused(t *testing.T) {
	path := writeCredential(t, t.TempDir(), "group.pin", "123456", 0o440)
	source, err := NewLockedFileSource(map[string]string{"device": path})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := source.PIN(context.Background(), "device"); err == nil || value != nil {
		t.Fatal("a group-readable credential with no ACL was accepted")
	}
}

// An ACL the guard cannot understand is refused, whatever it might have granted.
func TestAnACLThatCannotBeParsedIsRefused(t *testing.T) {
	if ownerOnly(-1, 0o400) {
		t.Fatal("a descriptor whose ACL cannot be read was accepted")
	}
	if ownerOnly(-1, 0o404) {
		t.Fatal("a world-readable mode was accepted")
	}
}
