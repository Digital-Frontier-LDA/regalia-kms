package registry

import "fmt"

// A SECRET'S KEK MUST NOT ALSO BE AN UNWRAP KEY (regalia-kms-091).
//
// release-secret is granted per object and refused to agents outright (sv3.2, CB4A Model C), and
// what it serves is a data key unwrapped on the card. unwrap serves the same thing to its caller.
// So if an object that declares unwrap is bound to the key a secret's envelopes are wrapped under,
// a principal granted that unwrap -- an agent among them -- opens the secret's data key with no
// release-secret grant, no purpose check against the secret and no agent refusal. Refusing unwrap to
// agents would close the agent half and leave every workload granted unwrap holding the same route;
// refusing the manifest closes it for everyone and leaves unwrap meaning what it means.
//
// validateObject's slot rule already refuses two objects on one DECLARED slot, but it compares the
// device_id string, and a device_id is only a name: the drivers resolve a card by its serial (and,
// on a two-token card, its label), and a key is what is in the slot. So the comparison here is on
// the physical identities -- (backend, device_serial, object_id, token_label) and
// public_key_sha256 -- and only between a secret's bindings and an unwrap object's bindings. Two
// sign keys naming one card twice is a different question that this rule does not answer.
//
// This lives in its own file, and Load calls it from its return line, because
// mutation_sweep_round2_ledger_test.go pins registry.go by line number.
func unlessASecretKEKIsAnUnwrapKey(result *Registry, objects []custodyObject) (*Registry, error) {
	if err := validateSecretKEKsUnreachableByUnwrap(objects); err != nil {
		return nil, err
	}
	return result, nil
}

func validateSecretKEKsUnreachableByUnwrap(objects []custodyObject) error {
	declares := func(object *custodyObject, wanted ...string) bool {
		for _, operation := range object.Operations {
			for _, name := range wanted {
				if operation == name {
					return true
				}
			}
		}
		return false
	}
	// sameSlot is the physical coordinate: one card (backend and serial), one key on it (object_id,
	// canonical by validateBindingCoordinates), and one token where the card is two. An unlabelled
	// binding may resolve to either token of the card, as in the declared-slot rule.
	//
	// The backend clause treats yubikey-openpgp and nitrokey-pkcs11 as different cards even though
	// one PKCS#11 driver serves both (review F4). An OpenPGP-applet binding is today refused any
	// operation but sign by requireOpenPGPAppletBindingsAreServable at daemon start, so it cannot be
	// the unwrap object here; this rule does not itself refuse that alias.
	sameSlot := func(a, b Binding) bool {
		if a.DeviceSerial == "" || a.Backend != b.Backend || a.DeviceSerial != b.DeviceSerial || a.ObjectID != b.ObjectID {
			return false
		}
		return a.TokenLabel == b.TokenLabel || a.TokenLabel == "" || b.TokenLabel == ""
	}
	// pinsAt is every public_key_sha256 the manifest declares for the key in binding's slot: its own
	// and that of any binding, of any object, on the same slot. A secret that pins only its DevAut
	// fingerprint has no pin of its own, but if anything else in the manifest pins the key in that
	// slot, an unwrap binding pinning the same key elsewhere reaches it (review F2).
	pinsAt := func(binding Binding) map[string]bool {
		pins := map[string]bool{}
		if binding.PublicKeySHA256 != "" {
			pins[binding.PublicKeySHA256] = true
		}
		for _, object := range objects {
			for _, candidate := range object.Bindings {
				if candidate.PublicKeySHA256 != "" && sameSlot(binding, candidate) {
					pins[candidate.PublicKeySHA256] = true
				}
			}
		}
		return pins
	}
	sameKey := func(secret, other Binding) bool {
		if sameSlot(secret, other) {
			return true
		}
		otherPins := pinsAt(other)
		for pin := range pinsAt(secret) {
			if otherPins[pin] {
				return true
			}
		}
		return false
	}
	for index := range objects {
		secret := &objects[index]
		// seal-envelope writes envelopes under the same KEK that release-secret opens them with.
		if !declares(secret, "release-secret", "seal-envelope") {
			continue
		}
		for otherIndex := range objects {
			other := &objects[otherIndex]
			if otherIndex == index || !declares(other, "unwrap") {
				continue
			}
			for _, secretBinding := range secret.Bindings {
				for _, otherBinding := range other.Bindings {
					if sameKey(secretBinding, otherBinding) {
						return fmt.Errorf("registry object %q: its KEK is also bound to %q, which declares unwrap: an unwrap there would return this secret's data key without a release-secret grant", secret.ID, other.ID)
					}
				}
			}
		}
	}
	return nil
}
