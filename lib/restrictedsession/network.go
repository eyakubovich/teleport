// +build bpf,!386

/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package restrictedsession

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/aquasecurity/tracee/libbpfgo"
	"github.com/gravitational/trace"
)

// ipTrie wraps BPF LSM map to work with net.IPNet types
type ipTrie struct {
	bpfMap *libbpfgo.BPFMap
}

func newIPTrie(m *libbpfgo.Module, name string) (ipTrie, error) {
	t, err := m.GetMap(name)
	if err != nil {
		return ipTrie{}, trace.Wrap(err)
	}

	return ipTrie{
		bpfMap: t,
	}, nil
}

// Set upserts (prefixLen, prefix) -> value entry in BPF trie
func (t *ipTrie) Set(n net.IPNet, value []byte) {
	prefixLen, _ := n.Mask.Size()

	// Key format: Prefix length (4 bytes) followed by prefix
	key := make([]byte, 4+len(n.IP))

	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:], n.IP)

	t.bpfMap.Update(key, value)
}

// network restricts IPv4 and IPv6 related operations.
type network struct {
	mod    *libbpfgo.Module
	deny4  ipTrie
	allow4 ipTrie
	deny6  ipTrie
	allow6 ipTrie
}

func newNetwork(config *NetworkConfig, mod *libbpfgo.Module) (*network, error) {
	deny4, err := newIPTrie(mod, "ip4_denylist")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	allow4, err := newIPTrie(mod, "ip4_allowlist")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	deny6, err := newIPTrie(mod, "ip6_denylist")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	allow6, err := newIPTrie(mod, "ip6_allowlist")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	n := network{
		mod:    mod,
		deny4:  deny4,
		allow4: allow4,
		deny6:  deny6,
		allow6: allow6,
	}

	if err = n.start(config); err != nil {
		return nil, trace.Wrap(err)
	}

	return &n, err
}

func (n *network) start(config *NetworkConfig) error {
	hooks := []string{"socket_connect", "socket_sendmsg"}

	for _, hook := range hooks {
		if err := attachLSM(n.mod, hook); err != nil {
			return trace.Wrap(err)
		}
	}

	if err := n.register(n.deny4, n.deny6, config.Deny); err != nil {
		return trace.Wrap(err)
	}

	if err := n.register(n.allow4, n.allow6, config.Allow); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func ipv4MappedIPNet(ipnet net.IPNet) net.IPNet {
	ipnet.IP = ipnet.IP.To16()
	ones, _ := ipnet.Mask.Size()
	// IPv4 mapped address has a 96-bit fixed prefix
	ipnet.Mask = net.CIDRMask(96+ones, 128)
	return ipnet
}

func (n *network) register(trie4, trie6 ipTrie, ips []net.IPNet) error {
	for _, ipnet := range ips {
		ip := ipnet.IP.To4()
		if ip != nil {
			// IPv4 address
			ipnet.IP = ip
			trie4.Set(ipnet, unit)

			// Also add it to IPv6 trie as a mapped address.
			// Needed in case an AF_INET6 socket is used with
			// IPv4 translated address. The IPv6 stack will forward
			// it to IPv4 stack but that happens much lower than
			// the LSM hook.
			ipnet = ipv4MappedIPNet(ipnet)
			trie6.Set(ipnet, unit)
		} else {
			ip = ipnet.IP.To16()
			if ip == nil {
				return fmt.Errorf("%q is not an IPv4 or IPv6 address", ip.String())
			}

			trie6.Set(ipnet, unit)
		}
	}

	return nil
}

func (n *network) close() {
}
