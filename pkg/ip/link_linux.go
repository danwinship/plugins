// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ip

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
)

var (
	ErrLinkNotFound = errors.New("link not found")
)

// VethOptions contains options describing a veth interface
type VethOptions struct {
	// ContainerVethName is the name to assign to the interface inside the
	// container. (Required)
	ContainerVethName string
	// ContainerVethMAC is MAC to assign to the container veth. If unspecified, the
	// interface will get a random MAC.
	ContainerVethMAC string

	// HostVethName is the name to assign to the interface in the host network
	// namespace. If unspecified, the interface will get a random name starting with
	// "veth".
	HostVethName string

	// MTU is the MTU to assign to the veth interface (or 0 for the default).
	MTU int
}

// makeVethPair is called from within the container's network namespace
func makeVethPair(name, peer string, mtu int, mac string, hostNS ns.NetNS) (netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu,
		},
		PeerName:      peer,
		PeerNamespace: netlink.NsFd(int(hostNS.Fd())),
	}
	if mac != "" {
		m, err := net.ParseMAC(mac)
		if err != nil {
			return nil, err
		}
		veth.LinkAttrs.HardwareAddr = m
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, err
	}
	// Re-fetch the container link to get its creation-time parameters, e.g. index and mac
	veth2, err := netlink.LinkByName(name)
	if err != nil {
		netlink.LinkDel(veth) // try and clean up the link if possible.
		return nil, err
	}

	return veth2, nil
}

func peerExists(name string) bool {
	if _, err := netlink.LinkByName(name); err != nil {
		return false
	}
	return true
}

func makeVeth(options *VethOptions, hostNS ns.NetNS) (peerName string, veth netlink.Link, err error) {
	for i := 0; i < 10; i++ {
		if options.HostVethName != "" {
			peerName = options.HostVethName
		} else {
			peerName, err = RandomVethName()
			if err != nil {
				return
			}
		}

		veth, err = makeVethPair(options.ContainerVethName, peerName, options.MTU, options.ContainerVethMAC, hostNS)
		switch {
		case err == nil:
			return

		case os.IsExist(err):
			if peerExists(peerName) && options.HostVethName == "" {
				continue
			}
			err = fmt.Errorf("container veth name provided (%v) already exists", options.ContainerVethName)
			return

		default:
			err = fmt.Errorf("failed to make veth pair: %v", err)
			return
		}
	}

	// should really never be hit
	err = fmt.Errorf("failed to find a unique veth name")
	return
}

// RandomVethName returns string "veth" with random prefix (hashed from entropy)
func RandomVethName() (string, error) {
	entropy := make([]byte, 4)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random veth name: %v", err)
	}

	// NetworkManager (recent versions) will ignore veth devices that start with "veth"
	return fmt.Sprintf("veth%x", entropy), nil
}

func RenameLink(curName, newName string) error {
	link, err := netlink.LinkByName(curName)
	if err == nil {
		err = netlink.LinkSetName(link, newName)
	}
	return err
}

func ifaceFromNetlinkLink(l netlink.Link) net.Interface {
	a := l.Attrs()
	return net.Interface{
		Index:        a.Index,
		MTU:          a.MTU,
		Name:         a.Name,
		HardwareAddr: a.HardwareAddr,
		Flags:        a.Flags,
	}
}

// SetupVethWithOptions sets up a pair of virtual ethernet devices.
// Call SetupVethWithOptions from inside the container netns.  It will create both veth
// devices and move the host-side veth into the provided hostNS namespace.
// On success, SetupVethWithOptions returns (hostVeth, containerVeth, nil)
func SetupVethWithOptions(options *VethOptions, hostNS ns.NetNS) (net.Interface, net.Interface, error) {
	hostVethName, contVeth, err := makeVeth(options, hostNS)
	if err != nil {
		return net.Interface{}, net.Interface{}, err
	}

	var hostVeth netlink.Link
	err = hostNS.Do(func(_ ns.NetNS) error {
		hostVeth, err = netlink.LinkByName(hostVethName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q in %q: %v", hostVethName, hostNS.Path(), err)
		}

		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %v", hostVethName, err)
		}

		// we want to own the routes for this interface
		_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", hostVethName), "0")
		return nil
	})
	if err != nil {
		return net.Interface{}, net.Interface{}, err
	}
	return ifaceFromNetlinkLink(hostVeth), ifaceFromNetlinkLink(contVeth), nil
}

// SetupVethWithName sets up a pair of virtual ethernet devices. See
// SetupVethWithOptions for more details.
func SetupVethWithName(contVethName, hostVethName string, mtu int, contVethMac string, hostNS ns.NetNS) (net.Interface, net.Interface, error) {
	return SetupVethWithOptions(
		&VethOptions{
			ContainerVethName: contVethName,
			ContainerVethMAC:  contVethMac,
			HostVethName:      hostVethName,
			MTU:               mtu,
		},
		hostNS,
	)
}

// SetupVeth sets up a pair of virtual ethernet devices, with a randomly-generated
// host veth name. See SetupVethWithOptions for more details.
func SetupVeth(contVethName string, mtu int, contVethMac string, hostNS ns.NetNS) (net.Interface, net.Interface, error) {
	return SetupVethWithOptions(
		&VethOptions{
			ContainerVethName: contVethName,
			ContainerVethMAC:  contVethMac,
			MTU:               mtu,
		},
		hostNS,
	)
}

// DelLinkByName removes an interface link.
func DelLinkByName(ifName string) error {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return ErrLinkNotFound
		}
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	return nil
}

// DelLinkByNameAddr remove an interface and returns its addresses
func DelLinkByNameAddr(ifName string) ([]*net.IPNet, error) {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil, ErrLinkNotFound
		}
		return nil, fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	addrs, err := netlink.AddrList(iface, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP addresses for %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return nil, fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	out := []*net.IPNet{}
	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() {
			out = append(out, addr.IPNet)
		}
	}

	return out, nil
}

// GetVethPeerIfindex returns the veth link object, the peer ifindex of the
// veth, or an error. This peer ifindex will only be valid in the peer's
// network namespace.
func GetVethPeerIfindex(ifName string) (netlink.Link, int, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, -1, fmt.Errorf("could not look up %q: %v", ifName, err)
	}
	if _, ok := link.(*netlink.Veth); !ok {
		return nil, -1, fmt.Errorf("interface %q was not a veth interface", ifName)
	}

	// veth supports IFLA_LINK (what vishvananda/netlink calls ParentIndex)
	// on 4.1 and higher kernels
	peerIndex := link.Attrs().ParentIndex
	if peerIndex <= 0 {
		// Fall back to ethtool for 4.0 and earlier kernels
		e, err := ethtool.NewEthtool()
		if err != nil {
			return nil, -1, fmt.Errorf("failed to initialize ethtool: %v", err)
		}
		defer e.Close()

		stats, err := e.Stats(link.Attrs().Name)
		if err != nil {
			return nil, -1, fmt.Errorf("failed to request ethtool stats: %v", err)
		}
		n, ok := stats["peer_ifindex"]
		if !ok {
			return nil, -1, fmt.Errorf("failed to find 'peer_ifindex' in ethtool stats")
		}
		if n > 32767 || n == 0 {
			return nil, -1, fmt.Errorf("invalid 'peer_ifindex' %d", n)
		}
		peerIndex = int(n)
	}

	return link, peerIndex, nil
}
