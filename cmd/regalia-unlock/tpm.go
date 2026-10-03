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

// pcrValues reads the SHA-256 value of each PCR, one PCR_Read each, as {"<index>": "<64 hex>"} (wire v2).
func pcrValues(device tpmtransport.TPM, pcrs []int) (map[string]string, error) {
	values := make(map[string]string, len(pcrs))
	for _, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return nil, errors.New("PCRs must be 0-23")
		}
		selection := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
			{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr))}}}
		read, err := tpm2.PCRRead{PCRSelectionIn: selection}.Execute(device)
		if err != nil {
			return nil, fmt.Errorf("the TPM refused to read PCR %d (%v)", pcr, err)
		}
		if len(read.PCRValues.Digests) != 1 || len(read.PCRValues.Digests[0].Buffer) != sha256.Size ||
			!bytes.Equal(tpm2.Marshal(read.PCRSelectionOut), tpm2.Marshal(selection)) {
			return nil, fmt.Errorf("the TPM did not read PCR %d of the SHA-256 bank", pcr)
		}
		values[strconv.Itoa(pcr)] = hex.EncodeToString(read.PCRValues.Digests[0].Buffer)
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
// should, in the initrd) is met by quoting again, a few times.
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
	return nil, nil, nil, errors.New("the PCRs kept changing between the quote and their reading")
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
