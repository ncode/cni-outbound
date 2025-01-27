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
	logDrops      bool
}

func NewIPTablesManager(mainChainName, defaultAction string, dryRun, logDrops bool) (Manager, error) {
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
		logDrops:      logDrops,
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
			"--log-prefix", fmt.Sprintf(`"[CNI-OUTBOUND-%s-%s]"`, containerChain, m.defaultAction),
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

// buildRuleSpecs returns one or more rules to insert into the chain.
// Each returned element is a slice of strings representing the iptables arguments.
func (m *IPTablesManager) buildRuleSpecs(chainName, host, proto, port, action string) [][]string {
	// Base rule spec
	baseSpec := []string{"-d", host, "-p", proto, "--dport", port}

	// If dry-run => Always log + then ACCEPT
	if m.dryRun {
		return [][]string{
			append(append([]string{}, baseSpec...), "-j", "LOG", "--log-prefix", fmt.Sprintf(`"[CNI-OUTBOUND-%s-ACCEPTED]"`, chainName)),
			append(append([]string{}, baseSpec...), "-j", "ACCEPT"),
		}
	}

	// Normal mode. If this is a drop and logDrops == true => log + then drop
	if m.logDrops && strings.EqualFold(action, "DROP") {
		return [][]string{
			append(append([]string{}, baseSpec...), "-j", "LOG", "--log-prefix", fmt.Sprintf(`"[CNI-OUTBOUND-%s-BLOCKED]"`, chainName)),
			append(append([]string{}, baseSpec...), "-j", "DROP"),
		}
	}

	// Otherwise, just a single final rule: -j <action>
	return [][]string{
		append(append([]string{}, baseSpec...), "-j", action),
	}
}

func (m *IPTablesManager) AddRule(chainName string, rule OutboundRule) error {
	ruleSpecs := m.buildRuleSpecs(chainName, rule.Host, rule.Proto, rule.Port, rule.Action)

	// Add rules in reverse order so they end up in the correct order
	// (since we're using Insert at position 1 each time)
	for i := len(ruleSpecs) - 1; i >= 0; i-- {
		if err := m.ipt.Insert("filter", chainName, 1, ruleSpecs[i]...); err != nil {
			return fmt.Errorf("failed to add rule: %v", err)
		}
	}

	return nil
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

// buildExpectedRuleLines constructs the strings we'll search for in `iptables -S <chain>` output.
func (m *IPTablesManager) buildExpectedRuleLines(chainName string, host, proto, port, action string) []string {
	var lines []string
	ruleSets := m.buildRuleSpecs(chainName, host, proto, port, action)

	// iptables -S lines typically look like:
	//   -A <chainName> -d <host> -p <proto> --dport <port> -j <ACTION> ...
	// We'll create lines that we can search with strings.Contains().
	for _, rs := range ruleSets {
		// Start with `-A chainName` then the rest:
		line := "-A " + chainName + " " + strings.Join(rs, " ")
		lines = append(lines, line)
	}
	return lines
}

func (m *IPTablesManager) VerifyRules(chainName string, rules []OutboundRule) error {
	existingRules, err := m.ipt.List("filter", chainName)
	if err != nil {
		return err
	}

	// Verify each OutboundRule
	for _, rule := range rules {
		expectedLines := m.buildExpectedRuleLines(chainName, rule.Host, rule.Proto, rule.Port, rule.Action)
		for _, expectedLine := range expectedLines {
			found := false
			for _, existingRule := range existingRules {
				if strings.Contains(existingRule, expectedLine) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("rule not found: %s", expectedLine)
			}
		}
	}

	// Verify default action logging rule in dry-run mode
	if m.dryRun {
		defaultLogLine := fmt.Sprintf("-A %s -j LOG --log-prefix [CNI-OUTBOUND-DEFAULT-%s]", chainName, m.defaultAction)
		found := false
		for _, existingRule := range existingRules {
			if strings.Contains(existingRule, defaultLogLine) {
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
