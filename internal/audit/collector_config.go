package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	collectorDescriptorSchema   = "regalia.collector-config/v1"
	maxCollectorDescriptorBytes = 16 << 10
	collectorGenerationBase     = "/var/lib/regalia-etc/regalia/collector-v1/generations"
	collectorDaemonBase         = "/var/lib/regalia-etc/regalia-kms/collector-v1"
)

var (
	// Same node ID grammar as the daemon's internal/config and internal/admission.
	collectorDescriptorNode = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	collectorGenerationID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// CollectorDescriptorError is a fixed diagnostic safe to log without disclosing input.
type CollectorDescriptorError string

func (e CollectorDescriptorError) Error() string { return string(e) }

const (
	ErrCollectorDescriptorFormat        CollectorDescriptorError = "collector descriptor: invalid format"
	ErrCollectorDescriptorSchema        CollectorDescriptorError = "collector descriptor: unsupported schema"
	ErrCollectorDescriptorIdentity      CollectorDescriptorError = "collector descriptor: invalid node, site or generation"
	ErrCollectorDescriptorOrigin        CollectorDescriptorError = "collector descriptor: invalid HTTPS origin"
	ErrCollectorDescriptorPath          CollectorDescriptorError = "collector descriptor: invalid generation path or alias"
	ErrCollectorDescriptorRole          CollectorDescriptorError = "collector descriptor: invalid role"
	ErrCollectorDescriptorStream        CollectorDescriptorError = "collector descriptor: invalid stream projection"
	ErrCollectorDescriptorUninitialized CollectorDescriptorError = "collector descriptor: not decoded"
)

// CollectorRole selects the descriptor's client certificate and private-key paths.
type CollectorRole string

const (
	CollectorRoleDaemon      CollectorRole = "daemon"
	CollectorRoleNodeShipper CollectorRole = "node_shipper"
)

type collectorRolePaths struct {
	cert, key string
}

// CollectorDescriptor contains decoded configuration only. Paths have been
// checked lexically. No files have been opened or credentials or identities verified.
type CollectorDescriptor struct {
	nodeID, site, generation string
	origin, ca, receiptKeys  string
	daemon, nodeShipper      collectorRolePaths
}

func (d CollectorDescriptor) NodeID() string     { return d.nodeID }
func (d CollectorDescriptor) Site() string       { return d.site }
func (d CollectorDescriptor) Generation() string { return d.generation }

// DecodeCollectorDescriptor decodes one bounded v1 document without I/O.
func DecodeCollectorDescriptor(data []byte) (CollectorDescriptor, error) {
	if len(data) > maxCollectorDescriptorBytes || !utf8.Valid(data) {
		return CollectorDescriptor{}, ErrCollectorDescriptorFormat
	}
	fields, ok := collectorDescriptorObject(data, "schema", "node_id", "site", "generation", "origin", "ca_path", "receipt_keys_path", "daemon", "node_shipper")
	if !ok {
		return CollectorDescriptor{}, ErrCollectorDescriptorFormat
	}

	var schema string
	var d CollectorDescriptor
	for key, target := range map[string]*string{
		"schema": &schema, "node_id": &d.nodeID, "site": &d.site, "generation": &d.generation,
		"origin": &d.origin, "ca_path": &d.ca, "receipt_keys_path": &d.receiptKeys,
	} {
		if json.Unmarshal(fields[key], target) != nil || *target == "" {
			return CollectorDescriptor{}, ErrCollectorDescriptorFormat
		}
	}
	if d.daemon, ok = decodeCollectorRole(fields["daemon"]); !ok {
		return CollectorDescriptor{}, ErrCollectorDescriptorFormat
	}
	if d.nodeShipper, ok = decodeCollectorRole(fields["node_shipper"]); !ok {
		return CollectorDescriptor{}, ErrCollectorDescriptorFormat
	}

	if schema != collectorDescriptorSchema {
		return CollectorDescriptor{}, ErrCollectorDescriptorSchema
	}
	if !collectorDescriptorNode.MatchString(d.nodeID) || !collectorSitePattern.MatchString(d.site+".x") || !collectorGenerationID.MatchString(d.generation) {
		return CollectorDescriptor{}, ErrCollectorDescriptorIdentity
	}
	if !validCollectorDescriptorOrigin(d.origin) {
		return CollectorDescriptor{}, ErrCollectorDescriptorOrigin
	}

	generationRoot := collectorGenerationBase + "/" + d.generation
	publicRoot := generationRoot + "/public"
	daemonRoot := collectorDaemonBase + "/" + d.generation
	shipperRoot := generationRoot + "/shipper"
	if !collectorGenerationFile(d.ca, publicRoot) || !collectorGenerationFile(d.receiptKeys, publicRoot) ||
		!d.daemon.within(daemonRoot) || !d.nodeShipper.within(shipperRoot) {
		return CollectorDescriptor{}, ErrCollectorDescriptorPath
	}
	return d, nil
}

// collectorDescriptorObject compares decoded keys before inserting them, so alternate
// JSON escapes cannot bypass duplicate detection. Each role reuses the same rules.
func collectorDescriptorObject(data []byte, fields ...string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if first, err := decoder.Token(); err != nil || first != json.Delim('{') {
		return nil, false
	}
	values := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !slices.Contains(fields, key) {
			return nil, false
		}
		if _, exists := values[key]; exists {
			return nil, false
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, false
		}
		values[key] = raw
	}
	if last, err := decoder.Token(); err != nil || last != json.Delim('}') || len(values) != len(fields) {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return values, true
}

func decodeCollectorRole(data json.RawMessage) (collectorRolePaths, bool) {
	fields, ok := collectorDescriptorObject(data, "certificate_path", "private_key_path")
	if !ok {
		return collectorRolePaths{}, false
	}
	var role collectorRolePaths
	if json.Unmarshal(fields["certificate_path"], &role.cert) != nil || role.cert == "" ||
		json.Unmarshal(fields["private_key_path"], &role.key) != nil || role.key == "" {
		return collectorRolePaths{}, false
	}
	return role, true
}

func validCollectorDescriptorOrigin(origin string) bool {
	if strings.ContainsAny(origin, "?#") || ValidateSinkURL(origin) != nil {
		return false
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Hostname() != ""
}

func collectorGenerationFile(name, root string) bool {
	// The root plus slash implies an absolute proper descendant. path.Clean
	// checks the appliance's POSIX spelling independently of the caller's OS.
	return strings.HasPrefix(name, root+"/") && name == path.Clean(name) && strings.IndexFunc(name, unicode.IsControl) == -1
}

func (r collectorRolePaths) within(root string) bool {
	// The two role roots are disjoint. Reject same-path aliases inside each
	// role as well. Only a later trusted file open can rule out inode aliases.
	return r.cert != r.key && collectorGenerationFile(r.cert, root) && collectorGenerationFile(r.key, root)
}

// EndpointOptions maps the selected role to C1 input paths without loading them.
func (d CollectorDescriptor) EndpointOptions(role CollectorRole) (CollectorEndpointOptions, error) {
	if d.generation == "" {
		return CollectorEndpointOptions{}, ErrCollectorDescriptorUninitialized
	}
	var paths collectorRolePaths
	switch role {
	case CollectorRoleDaemon:
		paths = d.daemon
	case CollectorRoleNodeShipper:
		paths = d.nodeShipper
	default:
		return CollectorEndpointOptions{}, ErrCollectorDescriptorRole
	}
	return CollectorEndpointOptions{
		Collector: d.origin, Site: d.site, CertificatePath: paths.cert, PrivateKeyPath: paths.key,
		CAPath: d.ca, ReceiptKeysPath: d.receiptKeys,
	}, nil
}

// ValidateStreams checks full site.trail names. The caller must provide the
// actual trusted registry projection. This method does not establish completeness.
func (d CollectorDescriptor) ValidateStreams(trails []string) error {
	if d.generation == "" {
		return ErrCollectorDescriptorUninitialized
	}
	if len(trails) == 0 {
		return ErrCollectorDescriptorStream
	}
	seen := make(map[string]struct{}, len(trails))
	for _, trail := range trails {
		if trail == "" || !collectorSitePattern.MatchString(d.site+"."+trail) {
			return ErrCollectorDescriptorStream
		}
		if _, exists := seen[trail]; exists {
			return ErrCollectorDescriptorStream
		}
		seen[trail] = struct{}{}
	}
	return nil
}
