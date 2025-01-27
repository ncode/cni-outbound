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
	dryRun        bool
}

func NewIPTablesManager(mainChainName, defaultAction string, dryRun bool) (Manager, error) {
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
		dryRun:        dryRun,
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

	if m.dryRun {
		// In dry-run mode, add a logging rule for anything that reaches the default action
		logRuleSpec := []string{
			"-j", "LOG",
			"--log-prefix", fmt.Sprintf("[CNI-OUTBOUND-DEFAULT-%s] ", m.defaultAction),
		}
		if err := m.ipt.Append("filter", containerChain, logRuleSpec...); err != nil {
			return fmt.Errorf("failed to add default action logging rule: %v", err)
		}
	}

	// Set the default action - even in dry-run mode we'll ACCEPT everything after logging
	defaultAction := "ACCEPT"
	if !m.dryRun {
		defaultAction = m.defaultAction
	}

	if err := m.ipt.Append("filter", containerChain, "-j", defaultAction); err != nil {
		return fmt.Errorf("failed to set default action for container chain: %v", err)
	}

	return nil
}

func (m *IPTablesManager) AddRule(chainName string, rule OutboundRule) error {
	// Build basic rule specification
	ruleSpec := []string{"-d", rule.Host, "-p", rule.Proto, "--dport", rule.Port}

	if m.dryRun {
		// Add logging rule with prefix based on original action
		logRuleSpec := append([]string{}, ruleSpec...)
		var logPrefix string
		if rule.Action == "DROP" {
			logPrefix = "[CNI-OUTBOUND-BLOCKED]"
		} else {
			logPrefix = "[CNI-OUTBOUND-ACCEPTED]"
		}

		logRuleSpec = append(logRuleSpec,
			"-j", "LOG",
			"--log-prefix", logPrefix)

		if err := m.ipt.Insert("filter", chainName, 1, logRuleSpec...); err != nil {
			return fmt.Errorf("failed to add logging rule: %v", err)
		}

		// In dry-run mode, always ACCEPT after logging
		ruleSpec = append(ruleSpec, "-j", "ACCEPT")
	} else {
		// Normal mode - use the specified action
		ruleSpec = append(ruleSpec, "-j", rule.Action)
	}

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
		ruleSpec := fmt.Sprintf("-A %s -d %s -p %s --dport %s", chainName, rule.Host, rule.Proto, rule.Port)

		if m.dryRun {
			// Check for logging rule
			logRuleSpec := ruleSpec + " -j LOG"
			found := false
			for _, existingRule := range existingRules {
				if strings.Contains(existingRule, logRuleSpec) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("logging rule not found: %s", logRuleSpec)
			}

			// Check for ACCEPT rule
			acceptRuleSpec := ruleSpec + " -j ACCEPT"
			found = false
			for _, existingRule := range existingRules {
				if strings.Contains(existingRule, acceptRuleSpec) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("ACCEPT rule not found: %s", acceptRuleSpec)
			}
		} else {
			// Original rule verification
			ruleSpec = ruleSpec + fmt.Sprintf(" -j %s", rule.Action)
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
	}

	// Verify default action logging rule in dry-run mode
	if m.dryRun {
		defaultLogRuleSpec := fmt.Sprintf("-j LOG.*%s", fmt.Sprintf("[CNI-OUTBOUND-DEFAULT-%s]", m.defaultAction))
		found := false
		for _, existingRule := range existingRules {
			if strings.Contains(existingRule, defaultLogRuleSpec) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("default action logging rule not found")
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
