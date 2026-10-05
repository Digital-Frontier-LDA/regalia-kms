package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	tpmtransport "github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// The TPM is spoken to through go-tpm, the standard Go library for it: its transport (which waits for
// the kernel's TPM device to have a response before reading it), its TPM2_Quote, and its parsing of
// what comes back. Nothing here writes or reads a TPM structure by hand.

// akHandle is attest.AK_HANDLE: where node-init makes the attestation key persistent.
const akHandle = tpm2.TPMHandle(0x81010002)

// openTPM opens the TPM: the kernel's resource-manager device, or (for tests against a software TPM) a
// UNIX socket given as unix:PATH.
func openTPM(path string) (tpmtransport.TPMCloser, error) {
	if socket, ok := strings.CutPrefix(path, "unix:"); ok {
		return linuxudstpm.Open(socket)
	}
	return linuxtpm.Open(path)
}

// quoteCommand is TPM2_Quote by the attestation key, with its empty password authorization: over
// 32 bytes of qualifying data, under the key's own signing scheme, for one selection of SHA-256 PCRs.
func quoteCommand(name tpm2.TPM2BName, qualifying []byte, pcrs []int) (*tpm2.Quote, error) {
	if len(qualifying) != 32 || len(pcrs) == 0 {
		return nil, errors.New("a quote needs 32 bytes of qualifying data and at least one PCR")
	}
	selected := make([]uint, 0, len(pcrs))
	for _, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return nil, errors.New("PCRs must be 0-23")
		}
		selected = append(selected, uint(pcr))
	}
	return &tpm2.Quote{
		SignHandle:     tpm2.AuthHandle{Handle: akHandle, Name: name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: qualifying},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
			{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(selected...)}}},
	}, nil
}

// quoted returns the two values deploy/baremetal/attest.py's verifier takes from a quote: the signed
// TPMS_ATTEST, exactly as the TPM returned it, and its ECDSA signature in DER.
func quoted(response *tpm2.QuoteResponse) (attest, signature []byte, err error) {
	if response.Signature.SigAlg != tpm2.TPMAlgECDSA {
		return nil, nil, errors.New("the quote is not signed with ECDSA")
	}
	ecc, err := response.Signature.Signature.ECDSA()
	if err != nil || ecc.Hash != tpm2.TPMAlgSHA256 {
		return nil, nil, errors.New("the quote is not signed with ECDSA and SHA-256")
	}
	attest = response.Quoted.Bytes()
	if len(attest) == 0 || len(ecc.SignatureR.Buffer) == 0 || len(ecc.SignatureS.Buffer) == 0 {
		return nil, nil, errors.New("the TPM's quote is malformed")
	}
	signature, err = asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(ecc.SignatureR.Buffer), new(big.Int).SetBytes(ecc.SignatureS.Buffer)})
	if err != nil {
		return nil, nil, err
	}
	return attest, signature, nil
}

// initrdPCR11Line is the one plain line the client says before it quotes anything (#75, tier Q; regalia-kms-d9): PCR 11
// as the TPM holds it now, in the initrd phase (the unit runs after systemd-pcrphase-initrd), which is what the image's
// build record predicts for that phase (uki.pcr11). It is not a secret, an operator reads it on the console (the iLO's
// too) when a peer refuses the node for its PCR 11, and the boot test compares it with the value the host computes
// from the build record, never with one the guest computes. A PCR that cannot be read is said too; nothing else
// depends on this line. Read, it is a status line (the client's output, as "gave the key"); unread, a diagnostic.
func initrdPCR11Line(device tpmtransport.TPM) (line string, read bool) {
	values, err := pcrValues(device, []int{11})
	if err != nil || len(values["11"]) != 64 {
		reason := "no value"
		if err != nil {
			reason = err.Error()
		}
		return "regalia-unlock: initrd PCR 11 (sha256) could not be read: " + reason, false
	}
	return "regalia-unlock: initrd PCR 11 (sha256) = " + values["11"], true
}

// pcrValues reads the SHA-256 value of each PCR as {"<index>": "<64 hex>"} (wire v2): one PCR_Read over the
// whole selection, so they are read at one instant; a TPM that answers part of a selection per call (it may
// return at most eight) is asked again for the rest.
func pcrValues(device tpmtransport.TPM, pcrs []int) (map[string]string, error) {
	values := make(map[string]string, len(pcrs))
	remaining := map[int]bool{}
	for _, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return nil, errors.New("PCRs must be 0-23")
		}
		remaining[pcr] = true
	}
	for call := 0; len(remaining) > 0 && call < 4; call++ {
		wanted := make([]uint, 0, len(remaining))
		for pcr := range remaining {
			wanted = append(wanted, uint(pcr))
		}
		selection := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
			{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(wanted...)}}}
		read, err := tpm2.PCRRead{PCRSelectionIn: selection}.Execute(device)
		if err != nil {
			return nil, fmt.Errorf("the TPM refused to read the PCRs (%v)", err)
		}
		if len(read.PCRSelectionOut.PCRSelections) != 1 || read.PCRSelectionOut.PCRSelections[0].Hash != tpm2.TPMAlgSHA256 {
			return nil, errors.New("the TPM did not read the SHA-256 bank")
		}
		// the digests come in the order of the PCRs selected in the answer, lowest first
		var given []int
		for byteIndex, bits := range read.PCRSelectionOut.PCRSelections[0].PCRSelect {
			for bit := 0; bit < 8; bit++ {
				if bits&(1<<bit) != 0 {
					given = append(given, byteIndex*8+bit)
				}
			}
		}
		if len(given) == 0 || len(given) != len(read.PCRValues.Digests) {
			return nil, errors.New("the TPM's PCR reading does not match its selection")
		}
		for n, pcr := range given {
			if !remaining[pcr] || len(read.PCRValues.Digests[n].Buffer) != sha256.Size {
				return nil, fmt.Errorf("the TPM read PCR %d, which was not asked for, or not as SHA-256", pcr)
			}
			values[strconv.Itoa(pcr)] = hex.EncodeToString(read.PCRValues.Digests[n].Buffer)
			delete(remaining, pcr)
		}
	}
	if len(remaining) > 0 {
		return nil, errors.New("the TPM did not read every PCR asked for")
	}
	return values, nil
}

// pcrDigest is what a quote's pcrDigest holds when the PCRs have these values: SHA-256 over them, in index order.
func pcrDigest(values map[string]string) []byte {
	indices := make([]int, 0, len(values))
	for index := range values {
		i, _ := strconv.Atoi(index)
		indices = append(indices, i)
	}
	sort.Ints(indices)
	h := sha256.New()
	for _, i := range indices {
		raw, _ := hex.DecodeString(values[strconv.Itoa(i)])
		h.Write(raw)
	}
	return h.Sum(nil)
}

// tpmQuote asks the TPM for a quote by its attestation key, and reads the quoted PCRs beside it (wire v2): the
// values must hash to the quote's own digest, or the peer refuses them. A PCR extended between the two (nothing
// should, in the initrd) is met by quoting again, a few times; after that the quote goes without values (the
// request in version 1): the values only name a PCR in a peer's audit, and losing that is better than losing
// the unlock.
func tpmQuote(device tpmtransport.TPM, qualifying []byte, pcrs []int) (attest, signature []byte, values map[string]string, err error) {
	for try := 0; try < 3; try++ {
		attest, signature, err = tpmQuoteOnce(device, qualifying, pcrs)
		if err != nil {
			return nil, nil, nil, err
		}
		values, err = pcrValues(device, pcrs)
		if err != nil {
			return nil, nil, nil, err
		}
		quoted, err := quotedPCRDigest(attest)
		if err != nil {
			return nil, nil, nil, err
		}
		if bytes.Equal(quoted, pcrDigest(values)) {
			return attest, signature, values, nil
		}
	}
	return attest, signature, nil, nil
}

// tpmQuoteOnce asks the TPM for a quote by its attestation key.
func tpmQuoteOnce(device tpmtransport.TPM, qualifying []byte, pcrs []int) (attest, signature []byte, err error) {
	public, err := tpm2.ReadPublic{ObjectHandle: akHandle}.Execute(device)
	if err != nil {
		// e.g. TPM_RC_HANDLE: no attestation key at that handle (node-init was not run on this TPM)
		return nil, nil, fmt.Errorf("the TPM has no usable attestation key (%v)", err)
	}
	command, err := quoteCommand(public.Name, qualifying, pcrs)
	if err != nil {
		return nil, nil, err
	}
	response, err := command.Execute(device)
	if err != nil {
		// e.g. TPM_RC_LOCKOUT: dictionary-attack lockout (deploy/baremetal/tpm-lockout.sh)
		return nil, nil, fmt.Errorf("the TPM refused the quote (%v)", err)
	}
	return quoted(response)
}
