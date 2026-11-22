package audit

import (
	"crypto/sha256"
	"crypto/tls"
	"net/url"
	"time"

	"golang.org/x/sys/unix"
)

const (
	collectorSelectorPath    = "/var/lib/regalia-etc/regalia/collector-v1/active.json"
	maxCollectorCertBytes    = 128 << 10
	maxCollectorKeyBytes     = 64 << 10
	maxCollectorCABytes      = 256 << 10
	maxCollectorReceiptBytes = 64 << 10
)

// CollectorRoleError reports a fixed local refusal without exposing paths or
// underlying credential, OS, or transport diagnostics.
type CollectorRoleError string

func (e CollectorRoleError) Error() string { return string(e) }

const (
	ErrCollectorRoleFile     CollectorRoleError = "collector role: untrusted file"
	ErrCollectorRoleMaterial CollectorRoleError = "collector role: invalid material"
	ErrCollectorRoleSink     CollectorRoleError = "collector role: cannot construct sink"
)

// CollectorRoleBinding describes only the public inputs to one loaded sink.
// It is not a receipt or evidence that the other role is configured.
type CollectorRoleBinding struct {
	Role                             CollectorRole
	NodeID, Site, Generation, Stream string
	DescriptorSHA256, CASHA256       [32]byte
	ReceiptKeysSHA256                [32]byte
	ClientIdentity                   string
	NotBefore, NotAfter              time.Time
}

// LoadedCollectorRole retains the actual sink with the public binding from
// the same opened material. The zero value has no sink.
type LoadedCollectorRole struct {
	sink    *HTTPSink
	binding CollectorRoleBinding
}

func (loaded *LoadedCollectorRole) Sink() *HTTPSink               { return loaded.sink }
func (loaded *LoadedCollectorRole) Binding() CollectorRoleBinding { return loaded.binding }

// LoadCollectorRole builds a sink offline from the fixed root-owned
// canonical layout. The caller supplies the trusted registry member for a
// shipper or an empty trail for the daemon. The root installer must keep each
// generation immutable while in use. This reads one role, not an atomic
// cross-file or cross-role snapshot.
func LoadCollectorRole(role CollectorRole, trail string, now time.Time) (*LoadedCollectorRole, error) {
	root, err := unix.Open("/", collectorOpenFlags|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, ErrCollectorRoleFile
	}
	defer unix.Close(root)
	reader := collectorFileReader{root: root, owner: 0, seen: make(map[collectorFileID]struct{})}
	return loadCollectorRole(&reader, role, trail, now)
}

func loadCollectorRole(reader *collectorFileReader, role CollectorRole, trail string, now time.Time) (*LoadedCollectorRole, error) {
	switch role {
	case CollectorRoleDaemon:
		if trail != "" {
			return nil, ErrCollectorDescriptorStream
		}
	case CollectorRoleNodeShipper:
		if !trailNamePattern.MatchString(trail) {
			return nil, ErrCollectorDescriptorStream
		}
	default:
		return nil, ErrCollectorDescriptorRole
	}

	raw, err := reader.read(collectorSelectorPath, maxCollectorDescriptorBytes, false)
	if err != nil {
		return nil, err
	}
	descriptor, err := DecodeCollectorDescriptor(raw)
	if err != nil {
		return nil, err
	}
	opts, err := descriptor.EndpointOptions(role)
	if err != nil {
		return nil, err
	}
	stream := descriptor.Site()
	if role == CollectorRoleNodeShipper {
		if err := descriptor.ValidateStreams([]string{trail}); err != nil {
			return nil, err
		}
		stream += "." + trail
	}

	certPEM, err := reader.read(opts.CertificatePath, maxCollectorCertBytes, false)
	if err != nil {
		return nil, err
	}
	keyPEM, err := reader.read(opts.PrivateKeyPath, maxCollectorKeyBytes, true)
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, ErrCollectorRoleMaterial
	}
	leaf, err := parseEndpointLeaf(certificate, now)
	if err != nil {
		return nil, ErrCollectorRoleMaterial
	}
	ca, err := reader.read(opts.CAPath, maxCollectorCABytes, false)
	if err != nil {
		return nil, err
	}
	roots, err := parseEndpointRoots(ca, "collector CA")
	if err != nil {
		return nil, ErrCollectorRoleMaterial
	}
	receiptKeys, err := reader.read(opts.ReceiptKeysPath, maxCollectorReceiptBytes, false)
	if err != nil {
		return nil, err
	}
	if _, err := parseEndpointReceiptKeys(receiptKeys, "collector receipt keys"); err != nil {
		return nil, ErrCollectorRoleMaterial
	}
	identity, err := collectorCertificateIdentity(certPEM)
	if err != nil {
		return nil, ErrCollectorRoleMaterial
	}

	origin, err := url.Parse(opts.Collector)
	if err != nil {
		return nil, ErrCollectorRoleSink
	}
	client, err := NewMTLSHTTPClient(certificate, roots, origin.Hostname())
	if err != nil {
		return nil, ErrCollectorRoleSink
	}
	sink, err := NewHTTPSink(opts.Collector, client, 10*time.Second, stream)
	if err != nil {
		return nil, ErrCollectorRoleSink
	}
	return &LoadedCollectorRole{sink: sink, binding: CollectorRoleBinding{
		Role: role, NodeID: descriptor.NodeID(), Site: descriptor.Site(), Generation: descriptor.Generation(), Stream: stream,
		DescriptorSHA256: sha256.Sum256(raw), CASHA256: sha256.Sum256(ca), ReceiptKeysSHA256: sha256.Sum256(receiptKeys),
		ClientIdentity: identity, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
	}}, nil
}
