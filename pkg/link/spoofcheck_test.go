// Copyright 2021 CNI authors
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

package link

import (
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"
)

var _ = Describe("spoofcheck", func() {
	iface := "net0"
	mac := "02:00:00:00:12:34"
	id := "container99-net1"

	Context("setup", func() {
		It("succeeds", func() {
			fake := knftables.NewFake(knftables.BridgeFamily, spoofCheckTableName)
			sc := newSpoofCheckerWithNFT(iface, mac, id, fake)
			Expect(sc.Setup()).To(Succeed())

			assertExpectedChainsExist(fake,
				"prerouting",
				"cni-br-iface-container99-net1",
				"cni-br-iface-container99-net1-mac",
			)
			assertExpectedRulesExist(fake)
		})

		It("fails when nft is unavailable", func() {
			sc := newSpoofCheckerWithNFT(iface, mac, id, nil)
			Expect(sc.Setup()).Error().To(HaveOccurred())
		})
	})

	Context("teardown", func() {
		It("succeeds", func() {
			fake := knftables.NewFake(knftables.BridgeFamily, spoofCheckTableName)
			err := fake.ParseDump(nftRules)
			Expect(err).NotTo(HaveOccurred())

			sc := newSpoofCheckerWithNFT("", "", id, fake)
			Expect(sc.Teardown()).To(Succeed())

			assertExpectedChainsExist(fake,
				"prerouting",
			)
		})

		It("fails when nft is unavailable", func() {
			sc := newSpoofCheckerWithNFT(iface, mac, id, nil)
			Expect(sc.Teardown()).Error().To(HaveOccurred())
		})
	})

	Context("setup and teardown", func() {
		It("succeeds", func() {
			fake := knftables.NewFake(knftables.BridgeFamily, spoofCheckTableName)
			sc := newSpoofCheckerWithNFT(iface, mac, id, fake)
			Expect(sc.Setup()).To(Succeed())
			Expect(sc.Teardown()).To(Succeed())

			assertExpectedChainsExist(fake,
				"prerouting",
			)
		})
	})
})

var nftRules = `
add table bridge cni_spoofcheck {}
add chain bridge cni_spoofcheck prerouting { type filter hook prerouting priority -300 ; }
add chain bridge cni_spoofcheck cni-br-iface-container99-net1
add chain bridge cni_spoofcheck cni-br-iface-container99-net1-mac
add rule bridge cni_spoofcheck prerouting iifname == net0 jump cni-br-iface-container99-net1 comment "macspoofchk-container99-net1"
add rule bridge cni_spoofcheck cni-br-iface-container99-net1 jump cni-br-iface-container99-net1-mac comment "macspoofchk-container99-net1"
add rule bridge cni_spoofcheck cni-br-iface-container99-net1-mac ether saddr == 02:00:00:00:12:34 return comment "macspoofchk-container99-net1"
add rule bridge cni_spoofcheck cni-br-iface-container99-net1-mac drop comment "macspoofchk-container99-net1"
`

func assertExpectedChainsExist(fake *knftables.Fake, chains ...string) {
	for _, ch := range chains {
		chain := fake.Table.Chains[ch]
		Expect(chain).NotTo(BeNil(), "expected chain %q to exist", ch)
	}

	for ch := range fake.Table.Chains {
		found := slices.Contains(chains, ch)
		Expect(found).To(BeTrue(), "did not expect chain %q to exist", ch)
	}
}

func assertExpectedRulesExist(fake *knftables.Fake) {
	chain := fake.Table.Chains["cni-br-iface-container99-net1"]
	Expect(chain).NotTo(BeNil(), "expected chain %q to exist", "cni-br-iface-container99-net1")
	Expect(chain.Rules).To(HaveLen(1))
	Expect(chain.Rules[0].Rule).To(Equal("jump cni-br-iface-container99-net1-mac"))

	chain = fake.Table.Chains["cni-br-iface-container99-net1-mac"]
	Expect(chain).NotTo(BeNil(), "expected chain %q to exist", "cni-br-iface-container99-net1-mac")
	Expect(chain.Rules).To(HaveLen(2))
	Expect(chain.Rules[0].Rule).To(Equal("ether saddr == 02:00:00:00:12:34 return"))
	Expect(chain.Rules[1].Rule).To(Equal("drop"))
}
