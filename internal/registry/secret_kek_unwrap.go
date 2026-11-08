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
	sameKey := func(secret, other Binding) bool {
		if secret.PublicKeySHA256 != "" && secret.PublicKeySHA256 == other.PublicKeySHA256 {
			return true
		}
		if secret.DeviceSerial == "" || secret.Backend != other.Backend || secret.DeviceSerial != other.DeviceSerial || secret.ObjectID != other.ObjectID {
			return false
		}
		// An unlabelled binding may resolve to either token of the card, as in the slot rule.
		return secret.TokenLabel == other.TokenLabel || secret.TokenLabel == "" || other.TokenLabel == ""
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
