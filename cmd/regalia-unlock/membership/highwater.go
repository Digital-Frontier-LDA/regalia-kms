package membership

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// The TPM high-water anchor as membership.HighWater lays it out (its docstring, "THE FORMAT ON THE TPM"),
// read and never written: the initrd cannot take the writer's lock and repairs nothing. What it decides is
// what Store.load decides before it writes anything: the high-water, a chain below it refused (ROLLBACK),
// HighWater.verify(lock=False) against the chain, and the jump bound advance() would apply.

const (
	HighWaterIndex = 0x1500016 // the membership counter; base +1, record slots +4 and +5 (+2 and +3 are the heartbeat's)
	recordBytes    = 48
	maxJump        = 1000
	ntMask         = 0xF0
	ntCounter      = 0x10
	ntOrdinary     = 0x00
	nvWritten      = 0x20000000
	nvWriteLocked  = 0x800
	nvState        = nvWritten | nvWriteLocked
	recordTag      = "regalia-membership-record/v1\x00"
)

var anchorAttributes = map[string]uint32{"counter": 0x00060012, "base": 0x00062002, "slot": 0x00060002}

// policyAttributes are the counter's and the slots' masks when they are written under a policy (POLICYWRITE,
// #242 B): the node's approved-image policy, not the owner, writes them. The base never takes this mask.
var policyAttributes = map[string]uint32{"counter": 0x0006001A, "slot": 0x0006000A}

// Unusable is membership.Unusable: the TPM answered, and what it holds cannot serve as this node's anchor.
// Distinct from a plain Refused (the TPM did not answer, or a read failed on an index that is as it should be).
type Unusable struct{ Reason string }

func (u *Unusable) Error() string { return u.Reason }

func requireAnchor(condition bool, format string, args ...any) error {
	if condition {
		return nil
	}
	return &Unusable{Reason: fmt.Sprintf(format, args...)}
}

// NV is what the reader needs of a TPM: the NV indices it lists, an index's public area (its attributes,
// its size and its authPolicy, empty when it has none), and its bytes (read with the index's own
// authorization, as tpm2_nvread <index> -C <index> does).
type NV interface {
	Defined() (map[uint32]bool, error)
	Public(index uint32) (attributes uint32, size int, authPolicy []byte, err error)
	Read(index uint32, size int) ([]byte, error)
}

type highWater struct {
	nv          NV
	index, base uint32
	slots       [2]uint32
	policy      *lazyPolicy
}

// lazyPolicy is this node's approved-image write policy, asked for only when a policy-written index is met
// and at most once (HighWater.policy): nil source when the node has none configured.
type lazyPolicy struct {
	source func() ([]byte, error)
	asked  bool
	value  []byte
	err    error
}

func (p *lazyPolicy) get() ([]byte, error) {
	if p.source == nil {
		return nil, nil
	}
	if !p.asked {
		p.asked = true
		p.value, p.err = p.source()
		if p.err == nil && len(p.value) != sha256.Size {
			p.value, p.err = nil, refuse("the approved-image write policy must be 64 lowercase hex")
		}
	}
	return p.value, p.err
}

func newHighWater(nv NV, index uint32, policy func() ([]byte, error)) highWater {
	return highWater{nv: nv, index: index, base: index + 1, slots: [2]uint32{index + 4, index + 5}, policy: &lazyPolicy{source: policy}}
}

func name(index uint32) string { return fmt.Sprintf("0x%x", index) }

func (h highWater) public(index uint32) (uint32, int, []byte, error) {
	attributes, size, authPolicy, err := h.nv.Public(index)
	if err == nil {
		return attributes, size, authPolicy, nil
	}
	defined, err := h.nv.Defined()
	if err != nil {
		return 0, 0, nil, refuse("the TPM does not answer (tpm2_getcap handles-nv-index failed): the high-water anchor is unavailable (fail closed)")
	}
	if !defined[index] {
		return 0, 0, nil, &Unusable{Reason: fmt.Sprintf("cannot read NV index %s: the high-water anchor is unavailable (fail closed): the index is not defined", name(index))}
	}
	return 0, 0, nil, refuse("cannot read NV index %s: the high-water anchor is unavailable (fail closed): the TPM lists it and did not give it", name(index))
}

func (h highWater) read8(index uint32) (uint64, error) {
	data, err := h.nv.Read(index, 8)
	if err != nil || len(data) != 8 {
		return 0, refuse("cannot read 8 bytes from NV index %s", name(index))
	}
	return binary.BigEndian.Uint64(data), nil
}

// asDefined is HighWater._as_defined: the index's attributes are this anchor's, owner-written or, for the
// counter and the slots, written under a policy that must be this node's approved-image policy (#242 B).
func (h highWater) asDefined(index uint32, attributes uint32, authPolicy []byte, kind string) error {
	mask := attributes &^ nvState
	if written, ok := policyAttributes[kind]; ok && mask == written {
		policy, err := h.policy.get() // a policy that cannot be established refuses: never a guess, never Unusable
		if err != nil {
			return err
		}
		if policy == nil || !bytes.Equal(authPolicy, policy) {
			held, configured := "(none)", "and this node has none configured"
			if len(authPolicy) > 0 {
				held = hex.EncodeToString(authPolicy)
			}
			if policy != nil {
				configured = "not " + hex.EncodeToString(policy)
			}
			return &Unusable{Reason: fmt.Sprintf("the anchor's write policy is not this node's approved-image policy: NV index %s is written by policy %s, %s",
				name(index), held, configured)}
		}
	} else if want := anchorAttributes[kind]; mask != want {
		return &Unusable{Reason: fmt.Sprintf("NV index %s does not have this anchor's attributes (0x%x, not 0x%x): it can be "+
			"written or read otherwise than this software defines", name(index), mask, want)}
	}
	if kind == "base" {
		return requireAnchor(attributes&nvWriteLocked != 0, "base index %s is not write-locked", name(index))
	}
	return requireAnchor(attributes&nvWriteLocked == 0, "NV index %s is write-locked: no record can be written to it", name(index))
}

// baseValue is HighWater._base: both indices' attributes, then the base.
func (h highWater) baseValue() (uint64, error) {
	a, aSize, aPolicy, err := h.public(h.index)
	if err != nil {
		return 0, err
	}
	if err := requireAnchor(a&ntMask == ntCounter && a&nvWritten != 0, "NV index %s is not a written counter", name(h.index)); err != nil {
		return 0, err
	}
	if err := h.asDefined(h.index, a, aPolicy, "counter"); err != nil {
		return 0, err
	}
	if err := requireAnchor(aSize == 8, "NV index %s is %d bytes, not 8", name(h.index), aSize); err != nil {
		return 0, err
	}
	b, bSize, bPolicy, err := h.public(h.base)
	if err != nil {
		return 0, err
	}
	if err := requireAnchor(b&ntMask == ntOrdinary && b&nvWritten != 0 && b&nvWriteLocked != 0,
		"base index %s is not written and write-locked", name(h.base)); err != nil {
		return 0, err
	}
	if err := h.asDefined(h.base, b, bPolicy, "base"); err != nil {
		return 0, err
	}
	// another size is not this anchor's (Unusable, which a re-anchor repairs), not a TPM that failed (#336)
	if err := requireAnchor(bSize == 8, "NV index %s is %d bytes, not 8", name(h.base), bSize); err != nil {
		return 0, err
	}
	return h.read8(h.base)
}

// epoch is HighWater._epoch.
func (h highWater) epoch(base uint64) (uint64, error) {
	counter, err := h.read8(h.index)
	if err != nil {
		return 0, err
	}
	if err := requireAnchor(counter >= base, "the NV counter %d is below its base %d", counter, base); err != nil {
		return 0, err
	}
	return counter - base, nil
}

func (h highWater) value() (uint64, error) {
	base, err := h.baseValue()
	if err != nil {
		return 0, err
	}
	return h.epoch(base)
}

// SlotBytes is HighWater.slot_bytes: epoch || digest || tag.
func SlotBytes(epoch uint64, digest []byte) []byte {
	body := binary.BigEndian.AppendUint64(nil, epoch)
	body = append(body, digest...)
	tag := sha256.Sum256(append([]byte(recordTag), body...))
	return append(body, tag[:8]...)
}

type record struct {
	epoch  uint64
	digest string
}

// less orders records as Python compares (epoch, digest hex) tuples.
func (r record) less(o record) bool {
	return r.epoch < o.epoch || (r.epoch == o.epoch && r.digest < o.digest)
}

// slot is HighWater._slot: the record a slot holds, nil when it holds none (never written, or a cut write).
func (h highWater) slot(index uint32) (*record, error) {
	a, size, authPolicy, err := h.public(index)
	if err != nil {
		return nil, err
	}
	if err := requireAnchor(a&ntMask == ntOrdinary, "record index %s is not an ordinary index", name(index)); err != nil {
		return nil, err
	}
	if err := requireAnchor(size == recordBytes, "record index %s is %d bytes, not %d", name(index), size, recordBytes); err != nil {
		return nil, err
	}
	if err := h.asDefined(index, a, authPolicy, "slot"); err != nil {
		return nil, err
	}
	if a&nvWritten == 0 {
		return nil, nil
	}
	data, err := h.nv.Read(index, recordBytes)
	if err != nil || len(data) != recordBytes {
		return nil, refuse("cannot read %d bytes from the record index %s: the anchor is unavailable (fail closed)", recordBytes, name(index))
	}
	held := record{binary.BigEndian.Uint64(data[:8]), hex.EncodeToString(data[8:40])}
	if !bytes.Equal(data, SlotBytes(held.epoch, data[8:40])) {
		return nil, nil
	}
	return &held, nil
}

// record is HighWater._record: the valid slot with the highest epoch.
func (h highWater) record() (record, error) {
	var valid []record
	for _, index := range h.slots {
		held, err := h.slot(index)
		if err != nil {
			return record{}, err
		}
		if held != nil {
			valid = append(valid, *held)
		}
	}
	if len(valid) == 0 {
		return record{}, &Unusable{Reason: fmt.Sprintf("NO RECORD: neither record slot (%s, %s) holds a valid record: the anchor cannot tell which chain "+
			"this node accepted (fail closed); re-anchor it (MEMBERSHIP-RECOVERY.md)", name(h.slots[0]), name(h.slots[1]))}
	}
	newest := valid[0]
	for _, r := range valid[1:] {
		if newest.less(r) {
			newest = r
		}
	}
	for _, r := range valid {
		if err := requireAnchor(r.epoch != newest.epoch || r == newest, "the two record slots name different manifests at "+
			"epoch %d: the anchor is inconsistent (fail closed)", newest.epoch); err != nil {
			return record{}, err
		}
	}
	return newest, nil
}

// verify is HighWater.verify(digest_of, lock=False).
func (h highWater) verify(digestOf func(uint64) string) (uint64, error) {
	base, err := h.baseValue()
	if err != nil {
		return 0, err
	}
	hw, err := h.epoch(base)
	if err != nil {
		return 0, err
	}
	held, err := h.record()
	if err != nil {
		return 0, err
	}
	// hw-1 only above 0: a record at 2^64-1 plus one wraps to 0 (the tag is unkeyed, so one can be planted)
	if err := requireAnchor(held.epoch == hw || (hw > 0 && held.epoch == hw-1), "the TPM record is for epoch %d but the TPM high-water is %d: the anchor is "+
		"inconsistent (fail closed)", held.epoch, hw); err != nil {
		return 0, err
	}
	if held.digest != digestOf(held.epoch) {
		return 0, refuse("CONFLICT: the manifest at epoch %d is not the one this node's TPM recorded: a substituted chain is never anchored; "+
			"record an incident", held.epoch)
	}
	again, err := h.baseValue()
	if err != nil {
		return 0, err
	}
	now, err := h.epoch(again)
	if err != nil {
		return 0, err
	}
	if again != base || now != hw {
		return 0, refuse("this host's TPM anchor changed during the read: read again")
	}
	return hw, nil
}

// ReadChain is the reading half of Store._load: every envelope accepted in order from nothing, none
// repeating an epoch. Returns the manifests, epoch 1 first.
func ReadChain(envelopes []any, root any) ([]map[string]any, error) {
	if len(envelopes) == 0 {
		return nil, refuse("the membership file must hold a non-empty list of envelopes")
	}
	var current map[string]any
	manifests := make([]map[string]any, 0, len(envelopes))
	for _, envelope := range envelopes {
		next, err := Accept(current, envelope, root)
		if err != nil {
			return nil, err
		}
		if current != nil && Digest(next) == Digest(current) {
			epoch, _ := integer(next["epoch"])
			return nil, refuse("the stored chain repeats epoch %s", epoch)
		}
		manifests = append(manifests, next)
		current = next
	}
	return manifests, nil
}

// Anchored is Store.load without its writes, for a reader that may change nothing: the chain (from
// ReadChain) must reach the TPM high-water, its manifest at the recorded epoch must be the one the TPM
// recorded (the crash window, a record one epoch behind the counter, is accepted as verify(lock=False)
// accepts it), and it may not run further ahead than advance() would go. `policy` gives this node's
// approved-image write policy (nil: none configured), which a counter or slot written under a policy must
// carry (#242 B); it is called only when such an index is met, at most once, and its error refuses the
// read. Returns the high-water.
func Anchored(nv NV, manifests []map[string]any, policy func() ([]byte, error)) (uint64, error) {
	h := newHighWater(nv, HighWaterIndex, policy)
	hw, err := h.value()
	if err != nil {
		return 0, err
	}
	var epoch uint64
	if n := len(manifests); n > 0 {
		last, _ := integer(manifests[n-1]["epoch"])
		if !last.IsUint64() {
			return 0, refuse("epoch %s is out of range", last)
		}
		epoch = last.Uint64()
	}
	if epoch < hw {
		return 0, refuse("ROLLBACK: the membership on disk is epoch %d but the TPM high-water is %d; fetch the chain from a peer", epoch, hw)
	}
	// verify asks only for an epoch at or below the high-water, which the chain reaches (checked above); one
	// beyond the chain is still never indexed: "" matches no recorded digest, so it is a CONFLICT
	digestOf := func(e uint64) string {
		if e == 0 {
			return strings.Repeat("00", 32)
		}
		if e > uint64(len(manifests)) {
			return ""
		}
		return Digest(manifests[e-1])
	}
	if hw, err = h.verify(digestOf); err != nil {
		return 0, err
	}
	if epoch-hw > maxJump {
		return 0, refuse("epoch jump %d exceeds the bound %d: anomaly", epoch-hw, maxJump)
	}
	return hw, nil
}
