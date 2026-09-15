package registry

import (
	"strings"
	"testing"
)

// #75 closes the symmetric-key commissioning gap in two PRs. The first (#203) pinned the
// present-tense absence with three tripwires that turned green the moment the matrix entry and
// the driver branch landed together. This file is the positive form of those tripwires — the
// shape the matrix and the driver must hold for the foreseeable future, so a future editor who
// widens the entry (other backend, other operation) gets a red test whose message points at the
// gap.
//
// The four constraints are pinned by the three tests below:
//
//	1. aes-256/unwrap is advertised for nitrokey-pkcs11                 (TestAes256IsAdvertisedUnwrapOnlyOnNitrokeyPkcs11)
//	2. no other backend advertises aes-256 anywhere                     (TestAes256IsAdvertisedUnwrapOnlyOnNitrokeyPkcs11)
//	3. no other operation on aes-256 is advertised                      (TestAes256IsAdvertisedUnwrapOnlyOnNitrokeyPkcs11)
//	4. the same shape that the tripwire pinned refused now passes Load  (TestAes256UnwrapIsAcceptedByTheMatrixGate)
//
// Constraint 4 has a rsa2048 control (TestRsa2048UnwrapIsAcceptedByTheMatrixGate) so a
// regression in Load that refuses everything still trips the control and forces a closer look.

// TestAes256IsAdvertisedUnwrapOnlyOnNitrokeyPkcs11 pins the shape of the #75 matrix entry, in
// all four directions at once:
//
//   - aes-256/unwrap is present for nitrokey-pkcs11 (the operation the driver supports);
//   - no other backend advertises aes-256 (yubikey-piv is behind the piv build tag,
//     yubikey-openpgp and fido2 do not implement CKM_AES_KEY_WRAP_PAD);
//   - aes-256 advertises ONLY "unwrap" — wrap is the open design question tracked in #194, and
//     sign / key-agreement / certificate-sign / release-secret / seal-envelope are not
//     symmetric-key operations at all.
//
// Each violation names the gap in its error message so a future editor who widens the entry can
// find the constraint it broke. Tripwire-the-positive: this test is what the matrix's silence on
// aes-256 (#203's pinning PR) was replaced by, and what would re-pin the silence if a future
// editor unwound the entry without understanding why it was added.
func TestAes256IsAdvertisedUnwrapOnlyOnNitrokeyPkcs11(t *testing.T) {
	advertised, ok := Capabilities()["nitrokey-pkcs11"]["aes-256"]
	if !ok {
		t.Fatal(`Capabilities()["nitrokey-pkcs11"]["aes-256"] is missing. The driver's CKM_AES_KEY_WRAP_PAD branch is in place (#75); the matrix entry must follow.`)
	}
	if !advertised["unwrap"] {
		t.Fatal(`Capabilities()["nitrokey-pkcs11"]["aes-256"]["unwrap"] is false. The driver implements the unwrap path against a CKO_SECRET_KEY KEK; the matrix must advertise it.`)
	}
	if advertised["wrap"] {
		t.Fatal(`Capabilities()["nitrokey-pkcs11"]["aes-256"]["wrap"] is true. The wrap side is an open design question (#194): a symmetric KEK has no public half, so a wrap site would have to hold the same secret the unwrap site holds, which conflicts with the multi-site custody model. Do not advertise wrap until #194 is resolved.`)
	}
	for operation, allowed := range advertised {
		if operation == "unwrap" {
			continue
		}
		if allowed {
			t.Fatalf(`Capabilities()["nitrokey-pkcs11"]["aes-256"][%q] is true. aes-256 is a single CKO_SECRET_KEY operation; other operations belong on a different algorithm.`, operation)
		}
	}

	for backend, algorithms := range Capabilities() {
		if backend == "nitrokey-pkcs11" {
			continue
		}
		if _, present := algorithms["aes-256"]; present {
			t.Fatalf("backend %q advertises aes-256: the #75 decision is nitrokey-pkcs11 only. yubikey-piv is behind the piv build tag and invisible to go test ./..., and yubikey-openpgp / fido2 do not implement CKM_AES_KEY_WRAP_PAD.", backend)
		}
	}
}

// TestAes256UnwrapIsAcceptedByTheMatrixGate pins constraint 4 from the package comment: the same
// manifest shape that #203's tripwire pinned as refused is now loadable. The manifest is the
// byte-identical unwrap-only shape the tripwire used: algorithm=aes-256, operations=["unwrap"],
// binding with no kek_algorithm/kek_version (those are release-secret / seal-envelope fields
// only). Loading it exercises registry.validateBinding's supports() check against the matrix,
// which is the layer that proved the absence in the tripwire and proves the presence now.
//
// If this test fails with "aes-256/unwrap" in the error, the matrix entry drifted but not enough
// to trip the symmetry test above — for example, the row was added to a different backend, or
// the operation was renamed.
func TestAes256UnwrapIsAcceptedByTheMatrixGate(t *testing.T) {
	const object = `{"id":"sym-test","name":"AES-256 unwrap probe","kind":"symmetric-key","classification":"restricted","environment":"staging","owner":"security","purpose":"sym-purpose","custody":"hardware-envelope","algorithm":"aes-256","operations":["unwrap"],"policy_id":"test-policy","bindings":[{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"local-hsm","object_id":"01","key_check":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"planned"}],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}`
	_, err := Load(strings.NewReader(manifest(object)), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatalf("Load() = %v; aes-256/unwrap is advertised by nitrokey-pkcs11's matrix entry, so a manifest declaring that pairing must load. If the error cites aes-256/unwrap, the symmetry test above should also be red — they fail together.", err)
	}
}

// TestRsa2048UnwrapIsAcceptedByTheMatrixGate is the control for the manifest-load assertion above.
// It uses the byte-identical shape with algorithm=rsa2048 instead of aes-256, and Load must
// succeed for the same reason it always did: rsa2048/unwrap is the longest-standing entry in the
// nitrokey-pkcs11 matrix. Without this control, a regression that breaks Load for every manifest
// would let the aes-256 test pass for the wrong reason (the refusal is uniform, not specific).
func TestRsa2048UnwrapIsAcceptedByTheMatrixGate(t *testing.T) {
	const object = `{"id":"rsa-ctrl","name":"RSA-2048 unwrap control","kind":"symmetric-key","classification":"restricted","environment":"staging","owner":"security","purpose":"rsa-ctrl-purpose","custody":"hardware-envelope","algorithm":"rsa2048","operations":["unwrap"],"policy_id":"test-policy","bindings":[{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"local-hsm","object_id":"02","key_check":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"planned"}],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}`
	_, err := Load(strings.NewReader(manifest(object)), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatalf("rsa2048/unwrap is in nitrokey-pkcs11's matrix today; Load must accept this manifest. If this control fails alongside the aes-256 case, the breakage is in Load, not in the matrix. Load() = %v", err)
	}
}
