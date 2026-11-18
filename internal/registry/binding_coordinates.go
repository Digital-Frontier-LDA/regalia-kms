package registry

import (
	"errors"
	"regexp"
)

// AN OBJECT_ID HAS ONE SPELLING PER KEY (regalia-kms-091, review F1).
//
// The PKCS#11 driver hex-decodes object_id into CKA_ID (findObject), and the PIV driver parses it
// as a hexadecimal slot number, lower-casing it and dropping a "0x" first (parseSlot). So "0a" and
// "0A" are one key on one card, and "9c", "9C", "0x9c" and "09c" are one PIV slot. Every rule that
// compares object_id as a string -- the declared-slot rule and the secret-KEK rule -- would then
// see two keys where the card has one. Rather than teach each comparison the drivers' parsing, a
// binding on those backends must spell its object_id the one way the drivers' input reads back:
// lowercase hex, whole bytes, 1 to 64 of them for PKCS#11 (findObject's bounds) and exactly one
// byte for PIV. The schema says the same (config/custody-manifest.schema.json).
//
// fido2 object_ids are names, not key coordinates, and are left as they are.
//
// This lives in its own file, and validateBinding calls it in place of the three lines it
// replaced, because mutation_sweep_round2_ledger_test.go pins registry.go by line number.
var (
	pkcs11ObjectIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{2}){1,64}$`)
	pivSlotPattern        = regexp.MustCompile(`^[0-9a-f]{2}$`)
)

func validateBindingCoordinates(binding Binding) error {
	if binding.Site == "" || binding.DeviceID == "" || binding.ObjectID == "" {
		return errors.New("binding site, device_id and object_id are required")
	}
	switch binding.Backend {
	case "nitrokey-pkcs11", "yubikey-openpgp":
		if !pkcs11ObjectIDPattern.MatchString(binding.ObjectID) {
			return errors.New("a PKCS#11 object_id must be lowercase hex, 1 to 64 whole bytes: the driver decodes it, so any other spelling names the same key twice")
		}
	case "yubikey-piv":
		if !pivSlotPattern.MatchString(binding.ObjectID) {
			return errors.New("a PIV object_id must be the slot as two lowercase hex digits: the driver parses it, so any other spelling names the same slot twice")
		}
	}
	return nil
}
