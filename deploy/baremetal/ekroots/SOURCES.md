# Where the EK root pins come from (regalia-kms-x6x)

`PINS` pins two roots, Infineon OPTIGA(TM) RSA Root CA and ECC Root CA, and the keys of the two CAs that
issued the first DL360's EK certificates, Infineon OPTIGA(TM) RSA and ECC Manufacturing CA 029. Every pin
below was fetched from three public sources, independently, on 2026-11-10. **All three agree, byte for byte.**
Nothing was taken from the TPM, from the EK certificate's own AIA URL alone, or from a private source.

## The pins

| pin | SHA-256 | what is hashed |
|---|---|---|
| RSA root | `899e35474c9807eb4c7f2f7a12da0028fb250cd02154d0009fca7d9c66574f3b` | the certificate's DER (`infineon-optiga-rsa-root-ca.der`) |
| ECC root | `cfeb02fecd55ad7a73c6e1d11985d4c47dee248ab63dcb66091a2489660443c3` | the certificate's DER (`infineon-optiga-ecc-root-ca.der`) |
| RSA CA 029 key | `31c0aa4f072f1d9e4d7ff33e5bd27810e5d2d1019c06549bbc707a3180fa518e` | its SubjectPublicKeyInfo, DER |
| ECC CA 029 key | `942da2973e3523889c0766925767f3b207300838a67523b293bced843e59c53a` | its SubjectPublicKeyInfo, DER |

Both roots are self-signed, `OU=OPTIGA(TM) Devices`, valid 2013-07-26 to 2043-07-25.

## The sources

### 1. Infineon's PKI, over HTTPS (fetched 2026-11-10T14:32:45Z)

`curl --proto =https --fail`, with certificate verification against the system store (`ssl_verify_result` 0):

| URL | DER SHA-256 |
|---|---|
| https://pki.infineon.com/OptigaRsaRootCA/OptigaRsaRootCA.crt | `899e3547…66574f3b` |
| https://pki.infineon.com/OptigaEccRootCA/OptigaEccRootCA.crt | `cfeb02fe…660443c3` |
| https://pki.infineon.com/OptigaRsaMfrCA029/OptigaRsaMfrCA029.crt | `fc7160eaa18a03722b534aeaa4167fee44555a9f1d8e4d725d1b69cafd280946` (re-issue, 2023-02-08) |
| https://pki.infineon.com/OptigaEccMfrCA029/OptigaEccMfrCA029.crt | `766507db64abf98e14d1c3c754d09d480b981c0f782a2f397e58811808b9d759` (re-issue, 2023-02-08) |

The two CA 029 certificates are the same bytes regalia#595 fetched over plain HTTP from the EK certificates'
AIA on 2026-11-03.

### 2. Microsoft's TrustedTpm.cab, Authenticode verified (fetched 2026-11-10T14:33:14Z)

- URL: https://go.microsoft.com/fwlink/?linkid=2097925, redirected over HTTPS to
  https://download.microsoft.com/download/D/6/5/D65270B2-EAFD-43FD-B9BA-F65CA00B153E/TrustedTpm.cab
- `TrustedTpm.cab` SHA-256 `6cd97a6c90d2b4be594a47ffb6d95792169c5cef6498eb1c82dfebcf53da0e51`, 2998201 bytes
- Authenticode: `osslsigncode verify -in TrustedTpm.cab -CAfile ms-roots.pem -TSA-CAfile ms-roots.pem
  -CRLfile cs-crl.pem -TSA-CRLfile tsa-crl.pem`, **exit 0**: `Signature verification: ok`,
  `Signature CRL verification: ok`, `Timestamp Server Signature verification: ok`, `Number of verified
  signatures: 1`, `Succeeded`. Message digest in the signature and computed over the file are both
  `1B22B9A8225C066B31AAD5A559B3588CCDDFF74F833AA4912313150D1431C035`. Signer `CN=Microsoft Corporation`
  (serial `330000021D4D19C84ED70F574800000000021D`, valid 2026-04-16 to 2027-04-15) under
  `Microsoft Code Signing PCA 2024`, under `Microsoft Root Certificate Authority 2011`. Timestamp
  2026-10-23T18:11:12Z by `Microsoft Time-Stamp PCA 2010`, under `Microsoft Root Certificate Authority 2010`.
- The trust anchors given to osslsigncode (`ms-roots.pem`), over HTTPS from Microsoft's PKI repository:
  - https://www.microsoft.com/pki/certs/MicRooCerAut2011_2011_03_22.crt, SHA-256
    `847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61` (SHA-1 `8f43288ad272f3103b6fb1428485ea3014c0bcfe`)
  - https://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt, SHA-256
    `df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e` (SHA-1 `3b1efd3a66ea28b16697394703a72ca340a05bd5`)
- The CRLs, over HTTPS (osslsigncode's own fetch of the CRL distribution points over HTTP failed on the
  content type): https://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl (lastUpdate
  2026-11-02) and https://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl
  (lastUpdate 2026-10-26).
- osslsigncode 2.9 (Debian trixie `osslsigncode_2.9-2_amd64.deb`, SHA-256
  `c62538b57f7d874ea7f8f750fd99c557a6adaf7fcfe9142fbb753b5a725a21c0`, by `apt-get download`, the archive's
  signed index), on OpenSSL 3.5.7. Extracted with 7-Zip.

| file in the cabinet | DER SHA-256 |
|---|---|
| `Infineon/RootCA/Infineon OPTIGA(TM) RSA Root CA.crt` | `899e3547…66574f3b` |
| `Infineon/RootCA/Infineon OPTIGA(TM) ECC Root CA.crt` | `cfeb02fe…660443c3` |
| `Infineon/IntermediateCA/OptigaRsaMfrCA029.crt` | `fc7160ea…fd280946` (the 2023 re-issue, = source 1) |
| `Infineon/IntermediateCA/OptigaEccMfrCA029.crt` | `766507db…08b9d759` (the 2023 re-issue, = source 1) |
| `Infineon/IntermediateCA/Infineon OPTIGA(TM) RSA Manufacturing CA 029_Issued_by_RootCA.crt` | `26203ada09d6b70ac18ab180c30dcda8c1292d89a435eaa56e1d822b1f598764` (as issued, 2017-08-21) |
| `Infineon/IntermediateCA/Infineon_OPTIGA(TM)_ECC_Manufacturing_CA_029.crt` | `de999c113baaed11133feb7731898c1f43dedbd5a75bb65d1662df46d5568acf` (as issued, 2017-08-21) |

### 3. Keylime's `tpm_cert_store` (fetched 2026-11-10T14:34:48Z)

Commit `8df08745bf81884af841c5235d8194db98d5e22e` of https://github.com/keylime/keylime (master that day),
each file from `https://raw.githubusercontent.com/keylime/keylime/<commit>/tpm_cert_store/<file>`:

| file | certificate's DER SHA-256 |
|---|---|
| `INF_RSA_010RT.pem` | `899e3547…66574f3b` |
| `INF_ECC_010RT.pem` | `cfeb02fe…660443c3` |

## CA 029: two certificates, one key ("AC3")

The CA 029 certificates exist twice per family: as issued on 2017-08-21 (TrustedTpm.cab, serials
`56FD0D6D` RSA and `431E3D04` ECC) and as re-issued on 2023-02-08 (Infineon's PKI, the cabinet and the EK
AIA; serials `5DBD83E8` and `17220490`). Each pair has the same subject, SKID and SubjectPublicKeyInfo, which
is why `PINS` pins the key. The first DL360's EK certificates were issued on 2017-10-07, before the re-issue
existed. `openssl verify` checks each certificate against the verification time. It does not require the
issuer to have been valid when the leaf was issued. So today both CA certificates verify the EKs. At
2017-10-08 only the 2017 one does, and the 2023 one gives `error 9 at 1 depth lookup: certificate is not yet
valid`. That output is captured in `servers/server-1.json` (`ac3.runs`), and
`tests/test_baremetal_ekchain.py` (`AC3`) reproduces it on a synthetic chain of the same shape and on the
public certificates.

## Rotating a pin

A new root or CA key (another server's EKs may name another manufacturing CA) is added the same way: fetched
from at least two of these sources that agree, with the URL, date and hashes added to this file, through a
pull request the owner signs off.
