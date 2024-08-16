package iptables

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

var newIPTables = func() (IPTablesWrapper, error) {
	return iptables.New()
}

type OutboundRule struct {
	Host   string
	Proto  string
	Port   string
	Action string
}

type Manager interface {
	EnsureMainChainExists() error
	CreateContainerChain(containerChain string) error
	AddRule(chainName string, rule OutboundRule) error
	AddJumpRule(sourceIP, targetChain string) error
	RemoveJumpRule(sourceIP, targetChain string) error
	ClearAndDeleteChain(chainName string) error
	ChainExists(chainName string) (bool, error)
	VerifyRules(chainName string, rules []OutboundRule) error
	RemoveJumpRuleByTargetChain(targetChain string) error
}

type IPTablesWrapper interface {
	NewChain(table, chain string) error
	ClearChain(table, chain string) error
	DeleteChain(table, chain string) error
	ChainExists(table, chain string) (bool, error)
	Append(table, chain string, rulespec ...string) error
	Insert(table, chain string, pos int, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	List(table, chain string) ([]string, error)
}

type IPTablesManager struct {
	ipt           IPTablesWrapper
	mainChainName string
	defaultAction string
}

func NewIPTablesManager(mainChainName, defaultAction string) (Manager, error) {
	ipt, err := newIPTables()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize iptables: %v", err)
	}

	if mainChainName == "" {
		mainChainName = "CNI-OUTBOUND"
	}

	if defaultAction == "" {
		defaultAction = "DROP"
	}

	return &IPTablesManager{
		ipt:           ipt,
		mainChainName: mainChainName,
		defaultAction: defaultAction,
	}, nil
}

func (m *IPTablesManager) EnsureMainChainExists() error {
	exists, err := m.ipt.ChainExists("filter", m.mainChainName)
	if err != nil {
		return fmt.Errorf("failed to check main chain existence: %v", err)
	}

	if !exists {
		if err := m.ipt.NewChain("filter", m.mainChainName); err != nil {
			return fmt.Errorf("failed to create main chain: %v", err)
		}
	}

	// Remove any existing rule in the CNI-FORWARD chain (in case it's in the wrong place)
	m.ipt.Delete("filter", "CNI-FORWARD", "-j", m.mainChainName)

	// Add the jump to CNI-OUTBOUND at the beginning of the CNI-FORWARD chain
	if err := m.ipt.Insert("filter", "CNI-FORWARD", 1, "-j", m.mainChainName); err != nil {
		return fmt.Errorf("failed to add jump to main chain in CNI-FORWARD: %v", err)
	}

	return nil
}

func (m *IPTablesManager) CreateContainerChain(containerChain string) error {
	if err := m.ipt.NewChain("filter", containerChain); err != nil {
		return fmt.Errorf("failed to create container chain: %v", err)
	}

	// Add rule for RELATED,ESTABLISHED connections
	if err := m.ipt.Append("filter", containerChain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to add RELATED,ESTABLISHED rule: %v", err)
	}

	// Set the default action for the container chain
	if err := m.ipt.Append("filter", containerChain, "-j", m.defaultAction); err != nil {
		return fmt.Errorf("failed to set default action for container chain: %v", err)
	}

	return nil
}

func (m *IPTablesManager) AddRule(chainName string, rule OutboundRule) error {
	ruleSpec := []string{"-d", rule.Host, "-p", rule.Proto, "--dport", rule.Port, "-j", rule.Action}
	return m.ipt.Insert("filter", chainName, 1, ruleSpec...)
}

func (m *IPTablesManager) AddJumpRule(sourceIP, targetChain string) error {
	return m.ipt.Append("filter", m.mainChainName, "-s", sourceIP, "-j", targetChain)
}

func (m *IPTablesManager) RemoveJumpRule(sourceIP, targetChain string) error {
	err := m.ipt.Delete("filter", m.mainChainName, "-s", sourceIP, "-j", targetChain)
	if err != nil {
		return fmt.Errorf("failed to remove jump rule: %v", err)
	}
	return nil
}

func (m *IPTablesManager) ClearAndDeleteChain(chainName string) error {
	if err := m.ipt.ClearChain("filter", chainName); err != nil {
		return fmt.Errorf("failed to clear chain %s: %v", chainName, err)
	}
	if err := m.ipt.DeleteChain("filter", chainName); err != nil {
		return fmt.Errorf("failed to delete chain %s: %v", chainName, err)
	}
	return nil
}

func (m *IPTablesManager) ChainExists(chainName string) (bool, error) {
	return m.ipt.ChainExists("filter", chainName)
}

func (m *IPTablesManager) VerifyRules(chainName string, rules []OutboundRule) error {
	existingRules, err := m.ipt.List("filter", chainName)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		ruleSpec := fmt.Sprintf("-A %s -d %s -p %s --dport %s -j %s", chainName, rule.Host, rule.Proto, rule.Port, rule.Action)
		found := false
		for _, existingRule := range existingRules {
			if strings.Contains(existingRule, ruleSpec) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("rule not found: %s", ruleSpec)
		}
	}

	return nil
}

func (m *IPTablesManager) RemoveJumpRuleByTargetChain(targetChain string) error {
	rules, err := m.ipt.List("filter", m.mainChainName)
	if err != nil {
		return fmt.Errorf("failed to list rules in main chain: %v", err)
	}

	for _, rule := range rules {
		if strings.Contains(rule, fmt.Sprintf("-j %s", targetChain)) {
			if err := m.ipt.Delete("filter", m.mainChainName, strings.Fields(rule)[2:]...); err != nil {
				return fmt.Errorf("failed to remove jump rule: %v", err)
			}
			return nil
		}
	}

	return fmt.Errorf("jump rule for chain %s not found", targetChain)
}
