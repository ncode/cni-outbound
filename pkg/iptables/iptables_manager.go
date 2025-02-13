package iptables

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

const table = "filter"

// OutboundRule describes a basic firewall rule: host, protocol, port, and the action (ACCEPT/DROP).
type OutboundRule struct {
	Host   string
	Proto  string
	Port   string
	Action string
}

// Manager defines the interface for creating chains, rules, etc.
type Manager interface {
	EnsureMainChainExists() error
	CreateContainerChain(containerChain string) error
	AddRule(chainName string, rule OutboundRule) error
	AddJumpRule(sourceIP, targetChain string) error
	RemoveJumpRule(sourceIP, targetChain string) error
	RemoveJumpRuleByTargetChain(targetChain string) error
	ClearAndDeleteChain(chainName string) error
	ChainExists(chainName string) (bool, error)
	VerifyRules(chainName string, rules []OutboundRule) error
}

// IPTablesWrapper is a minimal subset of go-iptables/iptables interfaces we rely on (for mocking in tests).
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

// IPTablesManager implements Manager using the go-iptables library.
type IPTablesManager struct {
	ipt           IPTablesWrapper
	mainChainName string
	defaultAction string
	logIdentifier string
	dryRun        bool
	logDrops      bool
}

// newIPTables is a function pointer for creating an iptables client (for mocking in tests).
var newIPTables = func() (IPTablesWrapper, error) {
	return iptables.New()
}

// NewIPTablesManager constructs the IPTablesManager with the specified main chain, default action, etc.
func NewIPTablesManager(mainChainName, defaultAction, logIdentifier string, dryRun, logDrops bool) (Manager, error) {
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
		logIdentifier: logIdentifier,
		dryRun:        dryRun,
		logDrops:      logDrops,
	}, nil
}

// EnsureMainChainExists creates the main chain if it doesn't exist and inserts a jump in CNI-FORWARD.
func (m *IPTablesManager) EnsureMainChainExists() error {
	exists, err := m.ipt.ChainExists(table, m.mainChainName)
	if err != nil {
		return fmt.Errorf("failed to check main chain existence: %v", err)
	}
	if !exists {
		if err := m.ipt.NewChain(table, m.mainChainName); err != nil {
			return fmt.Errorf("failed to create main chain: %v", err)
		}
	}

	// Remove any previous jump rule (just in case)
	_ = m.ipt.Delete(table, "CNI-FORWARD", "-j", m.mainChainName)

	// Insert jump to the main chain at the top of CNI-FORWARD.
	if err := m.ipt.Insert(table, "CNI-FORWARD", 1, "-j", m.mainChainName); err != nil {
		return fmt.Errorf("failed to add jump to main chain in CNI-FORWARD: %v", err)
	}
	return nil
}

// buildDefaultActionSpecs returns the iptables rule specs for the container chain's “final” default action.
// This consolidates all logic for dry-run, logging, and drop/accept in one place.
func (m *IPTablesManager) buildDefaultActionSpecs() [][]string {
	if m.dryRun {
		// In dry-run mode, we LOG (with defaultAction name) and then ACCEPT
		return [][]string{
			{"-j", "LOG", "--log-prefix", fmt.Sprintf("%s_%s ", m.defaultAction, m.logIdentifier)},
			{"-j", "ACCEPT"},
		}
	} else if strings.EqualFold(m.defaultAction, "DROP") && m.logDrops {
		// Normal mode, but defaultAction=DROP and logDrops=true => LOG then DROP
		return [][]string{
			{"-j", "LOG", "--log-prefix", fmt.Sprintf("%s_%s ", m.defaultAction, m.logIdentifier)},
			{"-j", "DROP"},
		}
	}
	// Otherwise, just a single rule with the default action (DROP or ACCEPT, no logging).
	return [][]string{
		{"-j", m.defaultAction},
	}
}

// CreateContainerChain makes a new chain for a specific container and sets up default rules.
func (m *IPTablesManager) CreateContainerChain(containerChain string) error {
	if err := m.ipt.NewChain(table, containerChain); err != nil {
		return fmt.Errorf("failed to create container chain: %v", err)
	}

	// Accept related and established connections first
	if err := m.ipt.Append(table, containerChain,
		"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to add RELATED,ESTABLISHED rule: %v", err)
	}

	// Now append the default action rule(s)
	for _, spec := range m.buildDefaultActionSpecs() {
		if err := m.ipt.Append(table, containerChain, spec...); err != nil {
			return fmt.Errorf("failed to set default action for container chain: %v", err)
		}
	}

	return nil
}

// buildRuleSpecs prepares the iptables arguments for a single OutboundRule.
func (m *IPTablesManager) buildRuleSpecs(host, proto, port, action string) [][]string {
	// Common rule spec
	baseSpec := []string{"-d", host, "-p", proto, "--dport", port}

	// If in dry-run, we log + ACCEPT
	if m.dryRun {
		return [][]string{
			append(append([]string{}, baseSpec...), "-j", "LOG", "--log-prefix",
				fmt.Sprintf("%s_%s ", action, m.logIdentifier)),
			append(append([]string{}, baseSpec...), "-j", "ACCEPT"),
		}
	}

	// If not dry-run but user wants logDrops, log + drop for DROP
	if m.logDrops && strings.EqualFold(action, "DROP") {
		return [][]string{
			append(append([]string{}, baseSpec...), "-j", "LOG", "--log-prefix",
				fmt.Sprintf("%s_%s ", action, m.logIdentifier)),
			append(append([]string{}, baseSpec...), "-j", "DROP"),
		}
	}

	// Normal case: single final rule
	return [][]string{
		append(append([]string{}, baseSpec...), "-j", action),
	}
}

// AddRule inserts a new rule (or rules) into the chain.
func (m *IPTablesManager) AddRule(chainName string, rule OutboundRule) error {
	ruleSpecs := m.buildRuleSpecs(rule.Host, rule.Proto, rule.Port, rule.Action)

	// Insert each spec at position 1 in reverse order so they appear in the chain in the correct sequence
	for i := len(ruleSpecs) - 1; i >= 0; i-- {
		if err := m.ipt.Insert(table, chainName, 1, ruleSpecs[i]...); err != nil {
			return fmt.Errorf("failed to add rule: %v", err)
		}
	}
	return nil
}

// AddJumpRule appends a jump from the main chain to the container chain for the given source IP.
func (m *IPTablesManager) AddJumpRule(sourceIP, targetChain string) error {
	return m.ipt.Append(table, m.mainChainName, "-s", sourceIP, "-j", targetChain)
}

// RemoveJumpRule deletes a jump rule referencing the targetChain for the given source IP.
func (m *IPTablesManager) RemoveJumpRule(sourceIP, targetChain string) error {
	if err := m.ipt.Delete(table, m.mainChainName, "-s", sourceIP, "-j", targetChain); err != nil {
		return fmt.Errorf("failed to remove jump rule: %v", err)
	}
	return nil
}

// RemoveJumpRuleByTargetChain does a more robust token-based matching to avoid partial strings.
func (m *IPTablesManager) RemoveJumpRuleByTargetChain(targetChain string) error {
	rules, err := m.ipt.List(table, m.mainChainName)
	if err != nil {
		return fmt.Errorf("failed to list rules in main chain: %v", err)
	}

	for _, ruleLine := range rules {
		tokens := strings.Fields(ruleLine)
		// Typically tokens start with "-A <chain>" then subsequent flags.
		// We want to find the position of "-j" and see if the next token matches targetChain.
		for i := 0; i < len(tokens); i++ {
			if tokens[i] == "-j" && i+1 < len(tokens) && tokens[i+1] == targetChain {
				// Found the rule referencing the targetChain
				// We also skip the first two tokens ("-A" <chainname>) when calling Delete
				toDelete := tokens[2:]
				if err := m.ipt.Delete(table, m.mainChainName, toDelete...); err != nil {
					return fmt.Errorf("failed to remove jump rule: %v", err)
				}
				return nil
			}
		}
	}

	return fmt.Errorf("jump rule for chain %s not found", targetChain)
}

// ClearAndDeleteChain first clears all rules from the chain, then deletes it.
func (m *IPTablesManager) ClearAndDeleteChain(chainName string) error {
	if err := m.ipt.ClearChain(table, chainName); err != nil {
		return fmt.Errorf("failed to clear chain %s: %v", chainName, err)
	}
	if err := m.ipt.DeleteChain(table, chainName); err != nil {
		return fmt.Errorf("failed to delete chain %s: %v", chainName, err)
	}
	return nil
}

// ChainExists checks whether the chain is present.
func (m *IPTablesManager) ChainExists(chainName string) (bool, error) {
	return m.ipt.ChainExists(table, chainName)
}

// VerifyRules verifies that each of the plugin's rules (and default actions) exist in iptables.
func (m *IPTablesManager) VerifyRules(chainName string, rules []OutboundRule) error {
	existingRules, err := m.ipt.List(table, chainName)
	if err != nil {
		return err
	}

	// For each user rule, build the expected lines and check if they exist
	for _, rule := range rules {
		expectedLines := m.buildExpectedRuleLines(chainName, rule.Host, rule.Proto, rule.Port, rule.Action)
		for _, expected := range expectedLines {
			if !lineExistsInIptablesList(expected, existingRules) {
				return fmt.Errorf("rule not found: %s", expected)
			}
		}
	}

	// Check for default rules if we're in dry-run mode:
	// (You could similarly check in all modes, but this preserves existing behavior.)
	if m.dryRun {
		defaultActionSpecs := m.buildDefaultActionSpecs()
		for _, spec := range defaultActionSpecs {
			expected := "-A " + chainName + " " + strings.Join(spec, " ")
			if !lineExistsInIptablesList(expected, existingRules) {
				return fmt.Errorf("default rule not found: %s", expected)
			}
		}
	}

	return nil
}

// buildExpectedRuleLines constructs the lines we'll look for in `iptables -S <chain>` output.
func (m *IPTablesManager) buildExpectedRuleLines(chainName, host, proto, port, action string) []string {
	specs := m.buildRuleSpecs(host, proto, port, action)
	lines := make([]string, 0, len(specs))
	for _, s := range specs {
		// iptables -S lines typically: "-A <chain> <args>..."
		line := "-A " + chainName + " " + strings.Join(s, " ")
		lines = append(lines, line)
	}
	return lines
}

// lineExistsInIptablesList checks if a constructed rule line appears in the actual iptables -S output lines.
func lineExistsInIptablesList(target string, existing []string) bool {
	for _, r := range existing {
		if r == target {
			return true
		}
	}
	return false
}
