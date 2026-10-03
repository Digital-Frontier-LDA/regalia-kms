package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	tpmtransport "github.com/google/go-tpm/tpm2/transport"
)

// tpmNV is membership.NV over the TPM, as tpm2-tools reads it for membership.HighWater: the NV indices
// the TPM lists (tpm2_getcap handles-nv-index), an index's public area (tpm2_nvreadpublic), and its bytes
// read with the owner's empty authorization (tpm2_nvread -C o; #190 keeps owner authorization empty).
// Nothing here writes to the TPM.
type tpmNV struct{ device tpmtransport.TPM }

func (n tpmNV) Defined() (map[uint32]bool, error) {
	defined := map[uint32]bool{}
	property := uint32(tpm2.TPMHTNVIndex) << 24
	for {
		response, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: property, PropertyCount: 64}.Execute(n.device)
		if err != nil {
			return nil, err
		}
		handles, err := response.CapabilityData.Data.Handles()
		if err != nil {
			return nil, err
		}
		for _, handle := range handles.Handle {
			if uint32(handle)>>24 != uint32(tpm2.TPMHTNVIndex) {
				return defined, nil
			}
			defined[uint32(handle)] = true
			property = uint32(handle) + 1
		}
		if !response.MoreData || len(handles.Handle) == 0 {
			return defined, nil
		}
	}
}

func (n tpmNV) public(index uint32) (*tpm2.TPMSNVPublic, tpm2.TPM2BName, error) {
	response, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(n.device)
	if err != nil {
		return nil, tpm2.TPM2BName{}, err
	}
	public, err := response.NVPublic.Contents()
	if err != nil {
		return nil, tpm2.TPM2BName{}, err
	}
	if uint32(public.NVIndex) != index {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("the TPM described NV index 0x%x for 0x%x", uint32(public.NVIndex), index)
	}
	return public, response.NVName, nil
}

// Public is the TPMA_NV mask, as one 32-bit value (tpm2_nvreadpublic's "value"), and the data size.
func (n tpmNV) Public(index uint32) (uint32, int, error) {
	public, _, err := n.public(index)
	if err != nil {
		return 0, 0, err
	}
	return binary.BigEndian.Uint32(tpm2.Marshal(public.Attributes)), int(public.DataSize), nil
}

func (n tpmNV) Read(index uint32, size int) ([]byte, error) {
	public, name, err := n.public(index)
	if err != nil {
		return nil, err
	}
	if size > int(public.DataSize) {
		return nil, fmt.Errorf("NV index 0x%x holds %d bytes, not %d", index, public.DataSize, size)
	}
	response, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: name},
		Size:       uint16(size),
	}.Execute(n.device)
	if err != nil {
		return nil, err
	}
	return response.Data.Buffer, nil
}
