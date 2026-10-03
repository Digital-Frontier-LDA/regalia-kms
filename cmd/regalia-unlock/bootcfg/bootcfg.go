// Package bootcfg renders, in the initrd, the boot credentials a host's ESP held until B3 (#66):
// the unlock configuration, the boot WireGuard configuration, the boot ruleset and boot.env, from the
// measured site document (regalia.site) and the manifest the chain verification accepted. It is
// deploy/baremetal/bootcreds.py's render() and read_site(), held to them byte for byte by
// tests/vectors/bootcreds-v1.json.
package bootcfg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

const (
	SiteSchema   = "regalia.boot-site/v1"
	siteMaxBytes = 16 * 1024
	bootSchema   = "regalia.unlock-boot/v1" // unlock.BOOT_SCHEMA
	table        = "regalia_boot"           // bootnet.TABLE
	bootIF       = "wg-boot"                // bootnet.BOOT_INTERFACE
)

// UnlockPCRs is bootcreds.UNLOCK_PCRS: the PCRs a booting host's quote covers.
var UnlockPCRs = []int{7, 11, 12}

var (
	nodeIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	interfacePattern = regexp.MustCompile(`^wg-[a-z0-9-]{1,12}$`)
	macPattern       = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	devicePattern    = regexp.MustCompile(`^[A-Za-z0-9/_.:=-]{1,255}$`)
	tpmNamePattern   = regexp.MustCompile(`^000b[0-9a-f]{64}$`)
	siteKeys         = []string{"schema", "host_ipv4", "device", "boot_mesh"}
	meshKeys         = []string{"node_id", "interface", "listen_port", "address", "unlock_port", "nic_mac", "prefix", "gateway", "peers"}
	peerKeys         = []string{"node_id", "underlay", "address"}
)

// Peer is one boot_mesh peer: where it is, outside the tunnel and inside.
type Peer struct{ NodeID, Underlay, Address string }

// Site is regalia.site, read and checked.
type Site struct {
	HostIPv4, Device                   string
	NodeID, Interface, Address, NICMAC string
	ListenPort, UnlockPort, Prefix     int
	Gateway                            string // "" for none (the peers are on the link)
	Peers                              []Peer
}

// Refused is a refusal, with the reason.
type Refused struct{ Reason string }

func (r *Refused) Error() string { return r.Reason }

func refuse(format string, args ...any) error { return &Refused{Reason: fmt.Sprintf(format, args...)} }

func exact(value any, keys []string, label string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, refuse("%s must be an object", label)
	}
	if len(object) != len(keys) {
		return nil, refuse("%s fields mismatch", label)
	}
	for _, k := range keys {
		if _, has := object[k]; !has {
			return nil, refuse("%s fields mismatch", label)
		}
	}
	return object, nil
}

// address is sitecfg._address: an IPv4 address as text, a host address (not unspecified, loopback,
// multicast, link-local or reserved).
func address(value any, label string) (netip.Addr, error) {
	text, ok := value.(string)
	if !ok {
		return netip.Addr{}, refuse("%s must be an IPv4 address, as text", label)
	}
	a, err := netip.ParseAddr(text)
	if err != nil || !a.Is4() || a.String() != text {
		return netip.Addr{}, refuse("%s must be an IPv4 address", label)
	}
	reserved := netip.MustParsePrefix("240.0.0.0/4").Contains(a)
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || reserved {
		return netip.Addr{}, refuse("%s must be a host address", label)
	}
	return a, nil
}

// port is sitecfg._port (and _boot_mesh's prefix): an integer in range, never a boolean.
func integer(value any, low, high int, message string) (int, error) {
	if _, isBool := value.(bool); isBool {
		return 0, refuse("%s", message)
	}
	n, ok := asInt(value)
	if !ok || n < low || n > high {
		return 0, refuse("%s", message)
	}
	return n, nil
}

func asInt(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case interface{ Int64() (int64, error) }:
		n, err := v.Int64()
		return int(n), err == nil && n >= -1<<31 && n < 1<<31
	}
	return 0, false
}

// ReadSite is bootcreds.read_site: strict JSON in canonical bytes, its boot_mesh checked by sitecfg's own
// rules (the zone and port checks need the whole site config, made when the file was written).
func ReadSite(raw []byte) (Site, error) {
	var site Site
	if len(raw) > siteMaxBytes {
		return site, refuse("regalia.site is at most %d bytes", siteMaxBytes)
	}
	document, err := membership.LoadDocument(raw)
	if err != nil {
		return site, refuse("regalia.site: %v", err)
	}
	if string(membership.Canonical(document)) != string(raw) {
		return site, refuse("regalia.site is not in canonical form")
	}
	doc, err := exact(document, siteKeys, "regalia.site")
	if err != nil {
		return site, err
	}
	if doc["schema"] != SiteSchema {
		return site, refuse("regalia.site: schema must be %s", SiteSchema)
	}
	device, ok := doc["device"].(string)
	if !ok || !devicePattern.MatchString(device) {
		return site, refuse("regalia.site: device must be a plain path")
	}
	host, err := address(doc["host_ipv4"], "host_ipv4")
	if err != nil {
		return site, err
	}
	site.HostIPv4, site.Device = host.String(), device
	if doc["boot_mesh"] == nil {
		return site, refuse("regalia.site: boot_mesh must not be null")
	}
	return site, readMesh(doc["boot_mesh"], host, &site)
}

// readMesh is sitecfg._boot_mesh, in the context read_site gives it (no KMS or SSH port, no zones).
func readMesh(value any, host netip.Addr, site *Site) error {
	mesh, err := exact(value, meshKeys, "boot_mesh")
	if err != nil {
		return refuse("regalia.site: boot_mesh must be null or hold exactly %v", meshKeys)
	}
	id, _ := mesh["node_id"].(string)
	if !nodeIDPattern.MatchString(id) {
		return refuse("regalia.site: boot_mesh.node_id is not a node ID")
	}
	iface, _ := mesh["interface"].(string)
	if !interfacePattern.MatchString(iface) || iface == bootIF {
		return refuse("regalia.site: boot_mesh.interface must be a WireGuard interface of its own")
	}
	if site.ListenPort, err = integer(mesh["listen_port"], 1, 65535, "regalia.site: boot_mesh.listen_port must be a port number 1-65535"); err != nil {
		return err
	}
	if site.UnlockPort, err = integer(mesh["unlock_port"], 1, 65535, "regalia.site: boot_mesh.unlock_port must be a port number 1-65535"); err != nil {
		return err
	}
	tunnel, err := address(mesh["address"], "boot_mesh.address")
	if err != nil {
		return refuse("regalia.site: %v", err)
	}
	mac, _ := mesh["nic_mac"].(string)
	if !macPattern.MatchString(mac) || mac == "00:00:00:00:00:00" || first(mac)&1 == 1 {
		return refuse("regalia.site: boot_mesh.nic_mac must be a unicast MAC address, lower case and colon-separated")
	}
	if site.Prefix, err = integer(mesh["prefix"], 1, 32, "regalia.site: boot_mesh.prefix must be a prefix length from 1 to 32"); err != nil {
		return err
	}
	if mesh["gateway"] != nil {
		gateway, err := address(mesh["gateway"], "boot_mesh.gateway")
		if err != nil {
			return refuse("regalia.site: %v", err)
		}
		link := netip.PrefixFrom(host, site.Prefix).Masked()
		if !link.Contains(gateway) || gateway == host {
			return refuse("regalia.site: boot_mesh.gateway must be another address inside %s (host_ipv4 and its prefix), or null", link)
		}
		if site.Prefix < 31 && (gateway == link.Addr() || gateway == broadcast(link)) {
			return refuse("regalia.site: boot_mesh.gateway must be a host of %s, not its network or broadcast address", link)
		}
		site.Gateway = gateway.String()
	}
	peers, ok := mesh["peers"].([]any)
	if !ok || len(peers) < 1 || len(peers) > 8 {
		return refuse("regalia.site: boot_mesh.peers must list 1 to 8 nodes")
	}
	if tunnel == host {
		return refuse("regalia.site: boot_mesh.address is the tunnel's address, not host_ipv4")
	}
	nodes, inside, outside := map[string]bool{id: true}, map[netip.Addr]bool{tunnel: true}, map[netip.Addr]bool{host: true}
	for i, value := range peers {
		label := fmt.Sprintf("boot_mesh.peers[%d]", i)
		peer, err := exact(value, peerKeys, label)
		if err != nil {
			return refuse("regalia.site: %s needs exactly %v", label, peerKeys)
		}
		pid, _ := peer["node_id"].(string)
		if !nodeIDPattern.MatchString(pid) || nodes[pid] {
			return refuse("regalia.site: %s.node_id must be another node's ID, listed once", label)
		}
		underlay, err := address(peer["underlay"], label+".underlay")
		if err != nil {
			return refuse("regalia.site: %v", err)
		}
		inner, err := address(peer["address"], label+".address")
		if err != nil {
			return refuse("regalia.site: %v", err)
		}
		if inside[inner] || outside[underlay] || outside[inner] || inside[underlay] || inner == underlay {
			return refuse("regalia.site: %s: no two nodes share an address, inside or outside the tunnel, and no address is both", label)
		}
		nodes[pid], inside[inner], outside[underlay] = true, true, true
		site.Peers = append(site.Peers, Peer{pid, underlay.String(), inner.String()})
	}
	site.NodeID, site.Interface, site.Address, site.NICMAC = id, iface, tunnel.String(), mac
	return nil
}

func first(mac string) byte {
	b, _ := hex.DecodeString(mac[:2])
	return b[0]
}

func broadcast(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= (1<<(32-p.Bits()) - 1)
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

type authorizer struct {
	node  map[string]any
	where Peer
}

// others is bootnet._others(cfg, manifest, "authorize"): the other nodes that may authorize, with their
// manifest entries and their addresses, sorted by node ID; a node that may and has no address is refused.
func others(site Site, manifest map[string]any) ([]authorizer, error) {
	nodes, err := membership.Validate(manifest)
	if err != nil {
		return nil, err
	}
	if _, named := nodes[site.NodeID]; !named {
		return nil, refuse("%s is not in the manifest", site.NodeID)
	}
	where := map[string]Peer{}
	for _, p := range site.Peers {
		where[p.NodeID] = p
	}
	var out []authorizer
	for _, entry := range manifest["nodes"].([]any) {
		node := entry.(map[string]any)
		id := node["node_id"].(string)
		if id == site.NodeID || !membership.May(manifest, id, "authorize") {
			continue
		}
		p, known := where[id]
		if !known {
			return nil, refuse("the site config has no boot-mesh address for %s, which the manifest lets authorize", id)
		}
		out = append(out, authorizer{node, p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].node["node_id"].(string) < out[j].node["node_id"].(string) })
	return out, nil
}

func wgKey(hexKey string) string {
	raw, _ := hex.DecodeString(hexKey)
	return base64.StdEncoding.EncodeToString(raw)
}

func set(values []string) string { return "{ " + strings.Join(values, ", ") + " }" }

// Render is bootcreds.render: {credential name: bytes}.
func Render(manifest map[string]any, site Site) (map[string][]byte, error) {
	peers, err := others(site, manifest)
	if err != nil {
		return nil, err
	}
	endpoints := map[string]string{}
	for _, p := range peers {
		endpoints[p.where.NodeID] = fmt.Sprintf("%s:%d", p.where.Address, site.UnlockPort)
	}
	// unlock.boot_config: the peers in the manifest's order
	var pins []any
	for _, entry := range manifest["nodes"].([]any) {
		node := entry.(map[string]any)
		id := node["node_id"].(string)
		endpoint, has := endpoints[id]
		if id == site.NodeID || !has || !membership.May(manifest, id, "authorize") {
			continue
		}
		for _, k := range []string{"ek_name", "ak_name"} {
			if !tpmNamePattern.MatchString(node[k].(string)) {
				return nil, refuse("peer.%s must be a SHA-256 TPM Name", k)
			}
		}
		pins = append(pins, map[string]any{"node_id": id, "endpoint": endpoint, "ek_name": node["ek_name"], "ak_name": node["ak_name"]})
	}
	if len(pins) == 0 {
		return nil, refuse("the manifest leaves %s no peer with an address", site.NodeID)
	}
	if len(pins) > 8 {
		return nil, refuse("peers must list 1 to 8 peers")
	}
	if !devicePattern.MatchString(site.Device) {
		return nil, refuse("device must be a plain path")
	}
	pcrs := make([]any, len(UnlockPCRs))
	for i, p := range UnlockPCRs {
		pcrs[i] = p
	}
	config := map[string]any{"schema": bootSchema, "node_id": site.NodeID, "device": site.Device, "pcrs": pcrs, "peers": pins}

	// bootnet.boot_wg_conf: by their WG-SERVICE keys, at their declared addresses, sorted by node ID
	wg := "[Interface]\n"
	var underlays, addresses []string
	for _, p := range peers {
		wg += fmt.Sprintf("\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\nEndpoint = %s:%d\n",
			p.where.NodeID, wgKey(p.node["wg_service_pub"].(string)), p.where.Address, p.where.Underlay, site.ListenPort)
		underlays, addresses = append(underlays, p.where.Underlay), append(addresses, p.where.Address)
	}
	ruleset := fmt.Sprintf(`# Generated by deploy/baremetal/bootnet.py for %[1]s under manifest epoch %[2]v. Do not edit by hand.
table inet %[3]s
delete table inet %[3]s
table inet %[3]s {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    meta nfproto ipv6 drop
    ct state invalid drop
    ct state established,related accept
    icmp type { destination-unreachable, time-exceeded } accept comment "path MTU discovery"
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
    meta nfproto ipv6 drop
    ct state invalid drop
    ct state established,related accept
    ip daddr %[4]s udp dport %[5]d accept comment "WireGuard, to the peers' declared addresses"
    oifname "%[6]s" ip saddr %[7]s ip daddr %[8]s tcp dport %[9]d tcp flags & (fin | syn | rst | ack) == syn ct state new accept comment "a new unlock request, inside the tunnel"
    icmp type { destination-unreachable, time-exceeded } accept comment "path MTU discovery"
  }
}
`, site.NodeID, manifest["epoch"], table, set(underlays), site.ListenPort, bootIF, site.Address, set(addresses), site.UnlockPort)
	env := fmt.Sprintf("BOOT_NIC_MAC=%s\nBOOT_ADDRESS=%s/%d\nBOOT_GATEWAY=%s\nBOOT_TUNNEL=%s\n", site.NICMAC, site.HostIPv4, site.Prefix, site.Gateway, site.Address)
	return map[string][]byte{
		"regalia.unlock-config": membership.Canonical(config),
		"regalia.wg-boot-conf":  []byte(wg),
		"regalia.boot-nft":      []byte(ruleset),
		"regalia.boot-env":      []byte(env),
	}, nil
}
