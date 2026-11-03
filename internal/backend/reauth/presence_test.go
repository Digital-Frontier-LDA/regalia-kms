package reauth

import "testing"

type readers map[string]uint64

func (r readers) Generation(name string) (uint64, bool) {
	generation, ok := r[name]
	return generation, ok
}

// A TOKEN PULLED AND PUT BACK BETWEEN TWO OPERATIONS IS AWAY (regalia-kms#72, G2): its reader's
// generation moved, though no operation saw it go.
func TestAMovedGenerationIsAnAbsence(t *testing.T) {
	watched := readers{"Nitrokey HSM 00": 7}
	var presence Presence
	presence.Watch(watched)
	if serve, away := presence.Check("hsm-a", "Nitrokey HSM 00", true); !serve || away {
		t.Fatalf("first look: serve %v away %v", serve, away)
	}
	if serve, away := presence.Check("hsm-a", "Nitrokey HSM 00", true); !serve || away {
		t.Fatalf("nothing happened: serve %v away %v", serve, away)
	}
	watched["Nitrokey HSM 00"] = 9 // pulled and back between two operations
	if serve, away := presence.Check("hsm-a", "Nitrokey HSM 00", true); !serve || !away {
		t.Fatalf("the generation moved: serve %v away %v, want an absence", serve, away)
	}
	if _, away := presence.Check("hsm-a", "Nitrokey HSM 00", true); away {
		t.Fatal("the same absence was reported twice")
	}
	// the same token now in another reader (another USB port) was away too
	watched["Nitrokey HSM 01"] = 10
	if _, away := presence.Check("hsm-a", "Nitrokey HSM 01", true); !away {
		t.Fatal("a token found in another reader was not away")
	}
}

// Fail closed: a removable token is refused while its reader is not watched (no watcher in this build,
// pcscd lost, the reader gone, no reader known for the slot); a slot that cannot be removed serves as
// before.
func TestARemovableTokenIsNeverServedUnwatched(t *testing.T) {
	var unwatched Presence
	if serve, _ := unwatched.Check("hsm-a", "Nitrokey HSM 00", true); serve {
		t.Fatal("a removable token was served with no watcher")
	}
	if serve, away := unwatched.Check("softhsm", "", false); !serve || away {
		t.Fatal("a slot that cannot be removed was refused")
	}
	var presence Presence
	presence.Watch(readers{"Nitrokey HSM 00": 1})
	for name, reader := range map[string]string{"a reader not watched": "Yubico YubiKey 00", "no reader for the slot": ""} {
		if serve, _ := presence.Check("hsm-a", reader, true); serve {
			t.Errorf("%s: served", name)
		}
	}
	if serve, _ := presence.Check("", "Nitrokey HSM 00", true); serve {
		t.Error("a nameless device was served")
	}
}
