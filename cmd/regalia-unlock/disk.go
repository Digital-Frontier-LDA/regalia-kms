package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	tokenType   = "regalia-peer-unlock"
	localName   = "regalia-unlock-local"
	maxReported = 16 // unusable tokens named in the diagnostics
)

// The key-type id at the head of a systemd encrypted credential: the TPM alone, or the TPM under a
// signed PCR policy as well. The local contribution is one of these two and nothing else.
var localKeyTypes = map[string]bool{"0c7cc07b117645919c4b0bea08bc20fe": true, "faf7eb9341e3412ca1a436f95a29362f": true}

// pathToken is the LUKS2 token of one peer path (deploy/baremetal/unlock.py, "ON THE DISK").
type pathToken struct {
	Type      string   `json:"type"`
	Keyslots  []string `json:"keyslots"`
	Version   int      `json:"version"`
	Target    string   `json:"target"`
	Peer      string   `json:"peer"`
	PathEpoch uint64   `json:"path_epoch"`
	Local     string   `json:"local"`
}

func (t *pathToken) validate(nodeID string) error {
	switch {
	case t.Version != wireVersion:
		return errors.New("it is not a version 1 token")
	case len(t.Keyslots) != 1:
		return errors.New("it does not name exactly one keyslot")
	case !nodeIDPattern.MatchString(t.Target) || !nodeIDPattern.MatchString(t.Peer) || t.Target == t.Peer:
		return errors.New("its target or peer is not a node ID")
	case t.Target != nodeID:
		return errors.New("it is for node " + t.Target)
	case t.PathEpoch < 1 || t.PathEpoch > maxEpoch:
		return errors.New("its path epoch is not an integer >= 1")
	}
	if slot, err := strconv.Atoi(t.Keyslots[0]); err != nil || slot < 0 || slot > 31 || strconv.Itoa(slot) != t.Keyslots[0] {
		return errors.New("its keyslot is not a keyslot number")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(t.Local), ""))
	if err != nil || len(t.Local) > 16384 || len(raw) < 16 || !localKeyTypes[hex.EncodeToString(raw[:16])] {
		return errors.New("its local contribution is not a systemd credential sealed to the TPM alone")
	}
	return nil
}

// The LUKS2 on-disk header (cryptsetup, "LUKS2 On-Disk Format Specification", section 2): a 4096-byte
// binary header, big-endian, followed by the JSON area; a second copy follows the first. Only the JSON
// metadata is read here. It holds no key: the tokens are public, and a forged header costs the unlock,
// nothing else.
const (
	luksBinaryHeader = 4096
	luksMinHeader    = 16384
	luksMaxHeader    = 4 * 1024 * 1024
)

type luksHeader struct {
	sequence uint64
	size     uint64
	json     []byte
}

// readLUKSHeader reads and checks one copy of the header at offset: the magic, the version, that the
// header says it is where it was found, and its SHA-256 checksum over the binary header and JSON area.
func readLUKSHeader(device io.ReaderAt, offset int64, magic string) (*luksHeader, error) {
	binaryHeader := make([]byte, luksBinaryHeader)
	if _, err := device.ReadAt(binaryHeader, offset); err != nil {
		return nil, errors.New("the device is too short for a LUKS2 header")
	}
	size := binary.BigEndian.Uint64(binaryHeader[8:16])
	switch {
	case string(binaryHeader[:6]) != magic || binary.BigEndian.Uint16(binaryHeader[6:8]) != 2:
		return nil, errors.New("not a LUKS2 header")
	case size < luksMinHeader || size > luksMaxHeader || size&(size-1) != 0:
		return nil, errors.New("the LUKS2 header states an impossible size")
	case binary.BigEndian.Uint64(binaryHeader[256:264]) != uint64(offset):
		return nil, errors.New("the LUKS2 header is not where it says it is")
	case string(bytes.TrimRight(binaryHeader[72:104], "\x00")) != "sha256":
		return nil, errors.New("the LUKS2 header's checksum is not SHA-256")
	}
	area := make([]byte, size-luksBinaryHeader)
	if _, err := device.ReadAt(area, offset+luksBinaryHeader); err != nil {
		return nil, errors.New("the device is too short for its LUKS2 header")
	}
	stated := append([]byte(nil), binaryHeader[448:480]...)
	for i := 448; i < 512; i++ {
		binaryHeader[i] = 0
	}
	sum := sha256.New()
	sum.Write(binaryHeader)
	sum.Write(area)
	if !bytes.Equal(sum.Sum(nil), stated) {
		return nil, errors.New("the LUKS2 header's checksum does not match")
	}
	if end := bytes.IndexByte(area, 0); end >= 0 {
		area = area[:end]
	}
	return &luksHeader{sequence: binary.BigEndian.Uint64(binaryHeader[16:24]), size: size, json: area}, nil
}

// luksMetadata returns the JSON metadata of the newer valid copy of the header, as cryptsetup chooses.
func luksMetadata(device io.ReaderAt) ([]byte, error) {
	primary, err := readLUKSHeader(device, 0, "LUKS\xba\xbe")
	var secondary *luksHeader
	if err == nil {
		secondary, _ = readLUKSHeader(device, int64(primary.size), "SKUL\xba\xbe")
	} else {
		for size := int64(luksMinHeader); size <= luksMaxHeader && secondary == nil; size *= 2 {
			secondary, _ = readLUKSHeader(device, size, "SKUL\xba\xbe")
		}
	}
	switch {
	case primary == nil && secondary == nil:
		return nil, errors.New("no valid LUKS2 header")
	case primary == nil || secondary != nil && secondary.sequence > primary.sequence:
		return secondary.json, nil
	}
	return primary.json, nil
}

// pathTokens reads the disk's path tokens for this node, by peer, the newest path epoch first (during
// a rotation the old keyslot is still there). Tokens that are not usable are reported, not fatal.
func pathTokens(device io.ReaderAt, nodeID string) (map[string][]pathToken, []string, error) {
	metadata, err := luksMetadata(device)
	if err != nil {
		return nil, nil, err
	}
	var header struct {
		Tokens map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(metadata, &header); err != nil {
		return nil, nil, errors.New("the LUKS2 metadata is not readable JSON")
	}
	ids := make([]string, 0, len(header.Tokens))
	for id := range header.Tokens {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	paths, skipped := map[string][]pathToken{}, []string{}
	for _, id := range ids {
		if _, err := strconv.ParseUint(id, 10, 16); err != nil {
			continue // a token ID is a small number; anything else is not printed, and not used
		}
		if len(skipped) >= maxReported {
			break
		}
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(header.Tokens[id], &kind) != nil || kind.Type != tokenType {
			continue
		}
		var token pathToken
		decoder := json.NewDecoder(bytes.NewReader(header.Tokens[id]))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&token); err != nil {
			skipped = append(skipped, "token "+id+": it has unknown or malformed fields")
			continue
		}
		if err := token.validate(nodeID); err != nil {
			skipped = append(skipped, "token "+id+": "+err.Error())
			continue
		}
		paths[token.Peer] = append(paths[token.Peer], token)
	}
	for _, tokens := range paths {
		sort.Slice(tokens, func(i, j int) bool { return tokens[i].PathEpoch > tokens[j].PathEpoch })
	}
	return paths, skipped, nil
}

// localContribution reads the node's half of the credential from the directory systemd passes the
// unit's credentials in ($CREDENTIALS_DIRECTORY, a private ramfs). systemd unsealed it with the TPM
// before this program was started (LoadCredentialEncrypted=): on another machine, or on a boot the
// TPM's policy does not accept, that fails and this program never runs.
func localContribution(directory string) ([]byte, error) {
	if directory == "" {
		return nil, errors.New("no credentials directory: this program is started by systemd with LoadCredentialEncrypted=" + localName)
	}
	local, err := os.ReadFile(filepath.Join(directory, localName))
	if err != nil || len(local) != secretBytes {
		wipe(local)
		return nil, errors.New("the credential " + localName + " is missing or is not 32 bytes")
	}
	return local, nil
}
