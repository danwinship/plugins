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
	"context"
	"fmt"
	"os"

	"sigs.k8s.io/knftables"
)

const (
	spoofCheckTableName     = "cni_spoofcheck"
	preRoutingBaseChainName = "prerouting"
)

type SpoofChecker struct {
	iface      string
	macAddress string
	refID      string
	nft        knftables.Interface
}

func NewSpoofChecker(iface, macAddress, refID string) *SpoofChecker {
	nft, err := knftables.New(knftables.BridgeFamily, spoofCheckTableName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spoofcheck: unable to create nftables interface: %v", err)
	}
	return newSpoofCheckerWithNFT(iface, macAddress, refID, nft)
}

func newSpoofCheckerWithNFT(iface, macAddress, refID string, nft knftables.Interface) *SpoofChecker {
	return &SpoofChecker{iface, macAddress, refID, nft}
}

// Setup applies nftables configuration to restrict traffic
// from the provided interface. Only traffic with the mentioned mac address
// is allowed to pass, all others are blocked.
// The configuration follows the format libvirt and ebtables implemented, allowing
// extensions to the rules in the future.
// refID is used to label the rules with a unique comment, identifying the rule-set.
//
// In order to take advantage of the nftables configuration change atomicity, the
// following steps are taken to apply the configuration:
// - Declare the table and chains (they will be created in case not present).
// - Apply the rules, while first flushing the iface/mac specific regular chain rules.
func (sc *SpoofChecker) Setup() error {
	if sc.nft == nil {
		return fmt.Errorf("no support for nftables")
	}

	tx := sc.nft.NewTransaction()

	tx.Add(&knftables.Table{})
	tx.Add(sc.baseChain())
	ifaceChain := sc.ifaceChain()
	tx.Add(ifaceChain)
	tx.Flush(ifaceChain)
	macChain := sc.macChain(ifaceChain.Name)
	tx.Add(macChain)
	tx.Flush(macChain)

	tx.Add(sc.matchIfaceJumpToChainRule(preRoutingBaseChainName, ifaceChain.Name))
	tx.Add(sc.jumpToChainRule(ifaceChain.Name, macChain.Name))
	tx.Add(sc.matchMacRule(macChain.Name))
	tx.Add(sc.dropRule(macChain.Name))

	if err := sc.nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("failed to setup spoof-check: %v", err)
	}
	return nil
}

func (sc *SpoofChecker) findPreroutingRule(ruleToFind *knftables.Rule) ([]*knftables.Rule, error) {
	if ruleToFind.Comment == nil {
		return nil, fmt.Errorf("cannot find rule without Comment")
	}

	allRules, err := sc.nft.ListRules(context.TODO(), preRoutingBaseChainName)
	if err != nil {
		return nil, err
	}

	matchRules := make([]*knftables.Rule, 0, 1)
	for _, rule := range allRules {
		if rule.Comment != nil && *rule.Comment == *ruleToFind.Comment {
			matchRules = append(matchRules, rule)
		}
	}
	return matchRules, nil
}

// Teardown removes the interface and mac-address specific chains and their rules.
// The table and base-chain are expected to survive while the base-chain rule that matches the
// interface is removed.
func (sc *SpoofChecker) Teardown() error {
	if sc.nft == nil {
		return fmt.Errorf("no support for nftables")
	}

	ifaceChain := sc.ifaceChain()
	expectedRuleToFind := sc.matchIfaceJumpToChainRule(preRoutingBaseChainName, ifaceChain.Name)

	rules, ifaceMatchRuleErr := sc.findPreroutingRule(expectedRuleToFind)
	if ifaceMatchRuleErr == nil && len(rules) > 0 {
		tx := sc.nft.NewTransaction()
		for _, rule := range rules {
			tx.Delete(rule)
		}
		if err := sc.nft.Run(context.TODO(), tx); err != nil {
			ifaceMatchRuleErr = fmt.Errorf("failed to delete iface match rule: %v", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "spoofcheck/teardown: unable to detect iface match rule for deletion: %+v", expectedRuleToFind)
	}

	tx := sc.nft.NewTransaction()
	tx.Delete(ifaceChain)
	tx.Delete(sc.macChain(ifaceChain.Name))

	var regularChainsErr error
	if err := sc.nft.Run(context.TODO(), tx); err != nil {
		regularChainsErr = fmt.Errorf("failed to delete regular chains: %v", err)
	}

	if ifaceMatchRuleErr != nil || regularChainsErr != nil {
		return fmt.Errorf("failed to teardown spoof-check: %v, %v", ifaceMatchRuleErr, regularChainsErr)
	}
	return nil
}

func (sc *SpoofChecker) matchIfaceJumpToChainRule(chain, toChain string) *knftables.Rule {
	return &knftables.Rule{
		Chain: chain,
		Rule: knftables.Concat(
			"iifname", "==", sc.iface,
			"jump", toChain,
		),
		Comment: ruleComment(sc.refID),
	}
}

func (sc *SpoofChecker) jumpToChainRule(chain, toChain string) *knftables.Rule {
	return &knftables.Rule{
		Chain: chain,
		Rule: knftables.Concat(
			"jump", toChain,
		),
		Comment: ruleComment(sc.refID),
	}
}

func (sc *SpoofChecker) matchMacRule(chain string) *knftables.Rule {
	return &knftables.Rule{
		Chain: chain,
		Rule: knftables.Concat(
			"ether saddr", "==", sc.macAddress,
			"return",
		),
		Comment: ruleComment(sc.refID),
	}
}

func (sc *SpoofChecker) dropRule(chain string) *knftables.Rule {
	return &knftables.Rule{
		Chain:   chain,
		Rule:    "drop",
		Comment: ruleComment(sc.refID),
	}
}

func (sc *SpoofChecker) baseChain() *knftables.Chain {
	return &knftables.Chain{
		Name:     preRoutingBaseChainName,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Priority: knftables.PtrTo(knftables.BaseChainPriority("-300")),
	}
}

func (sc *SpoofChecker) ifaceChain() *knftables.Chain {
	ifaceChainName := "cni-br-iface-" + sc.refID
	return &knftables.Chain{
		Name: ifaceChainName,
	}
}

func (sc *SpoofChecker) macChain(ifaceChainName string) *knftables.Chain {
	macChainName := ifaceChainName + "-mac"
	return &knftables.Chain{
		Name: macChainName,
	}
}

func ruleComment(id string) *string {
	const refIDPrefix = "macspoofchk-"
	name := refIDPrefix + id
	return &name
}
