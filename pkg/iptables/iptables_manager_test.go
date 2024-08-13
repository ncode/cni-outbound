package iptables

import (
	"errors"
	"strings"
	"testing"

	"slices"
)

// Mock implementation of iptables.IPTables
type mockIPTables struct {
	chains map[string]bool
	rules  map[string][]string
}

func newMockIPTables() *mockIPTables {
	return &mockIPTables{
		chains: make(map[string]bool),
		rules:  make(map[string][]string),
	}
}

func (m *mockIPTables) NewChain(table, chain string) error {
	m.chains[chain] = true
	return nil
}

func (m *mockIPTables) ClearChain(table, chain string) error {
	m.rules[chain] = []string{}
	return nil
}

func (m *mockIPTables) DeleteChain(table, chain string) error {
	delete(m.chains, chain)
	delete(m.rules, chain)
	return nil
}

func (m *mockIPTables) ChainExists(table, chain string) (bool, error) {
	return m.chains[chain], nil
}

func (m *mockIPTables) Append(table, chain string, rulespec ...string) error {
	m.rules[chain] = append(m.rules[chain], joinRule(chain, rulespec))
	return nil
}

func (m *mockIPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	rule := joinRule(chain, rulespec)
	m.rules[chain] = slices.Insert(m.rules[chain], pos-1, rule)
	return nil
}

func (m *mockIPTables) Delete(table, chain string, rulespec ...string) error {
	rule := joinRule(chain, rulespec)
	if i := slices.Index(m.rules[chain], rule); i != -1 {
		m.rules[chain] = slices.Delete(m.rules[chain], i, i+1)
		return nil
	}
	return errors.New("rule not found")
}

func (m *mockIPTables) List(table, chain string) ([]string, error) {
	return m.rules[chain], nil
}

func joinRule(chain string, rulespec []string) string {
	return "-A " + chain + " " + strings.Join(rulespec, " ")
}

func TestIPTablesManager(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}

	t.Run("EnsureMainChainExists", func(t *testing.T) {
		err := manager.EnsureMainChainExists()
		if err != nil {
			t.Errorf("EnsureMainChainExists failed: %v", err)
		}
		exists, _ := mockIpt.ChainExists("filter", "CNI-OUTBOUND")
		if !exists {
			t.Error("Main chain was not created")
		}
		rules, _ := mockIpt.List("filter", "FORWARD")
		expectedRule := "-A FORWARD -j CNI-OUTBOUND"
		if !slices.Contains(rules, expectedRule) {
			t.Errorf("Jump to CNI-OUTBOUND not added to FORWARD chain. Rules: %v", rules)
		}
	})

	t.Run("CreateContainerChain", func(t *testing.T) {
		err := manager.CreateContainerChain("CONTAINER_CHAIN")
		if err != nil {
			t.Errorf("CreateContainerChain failed: %v", err)
		}
		exists, _ := mockIpt.ChainExists("filter", "CONTAINER_CHAIN")
		if !exists {
			t.Error("Container chain was not created")
		}
		rules, _ := mockIpt.List("filter", "CONTAINER_CHAIN")
		if len(rules) != 2 {
			t.Errorf("Expected 2 rules in container chain, got %d", len(rules))
		}
		expectedRules := []string{
			"-A CONTAINER_CHAIN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
			"-A CONTAINER_CHAIN -j DROP",
		}
		for _, rule := range expectedRules {
			if !slices.Contains(rules, rule) {
				t.Errorf("Expected rule not found: %s", rule)
			}
		}
	})

	t.Run("AddRule", func(t *testing.T) {
		rule := OutboundRule{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"}
		err := manager.AddRule("CONTAINER_CHAIN", rule)
		if err != nil {
			t.Errorf("AddRule failed: %v", err)
		}
		rules, _ := mockIpt.List("filter", "CONTAINER_CHAIN")
		expectedRule := "-A CONTAINER_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT"
		if !slices.Contains(rules, expectedRule) {
			t.Errorf("Rule was not added correctly. Got %v, want %v", rules, expectedRule)
		}
	})

	t.Run("AddJumpRule", func(t *testing.T) {
		err := manager.AddJumpRule("10.0.0.1", "CONTAINER_CHAIN")
		if err != nil {
			t.Errorf("AddJumpRule failed: %v", err)
		}
		rules, _ := mockIpt.List("filter", "CNI-OUTBOUND")
		expectedRule := "-A CNI-OUTBOUND -s 10.0.0.1 -j CONTAINER_CHAIN"
		if !slices.Contains(rules, expectedRule) {
			t.Errorf("Jump rule was not added correctly. Got %v, want %v", rules, expectedRule)
		}
	})

	t.Run("RemoveJumpRule", func(t *testing.T) {
		err := manager.RemoveJumpRule("10.0.0.1", "CONTAINER_CHAIN")
		if err != nil {
			t.Errorf("RemoveJumpRule failed: %v", err)
		}
		rules, _ := mockIpt.List("filter", "CNI-OUTBOUND")
		unexpectedRule := "-A CNI-OUTBOUND -s 10.0.0.1 -j CONTAINER_CHAIN"
		if slices.Contains(rules, unexpectedRule) {
			t.Error("Jump rule was not removed")
		}
	})

	t.Run("ClearAndDeleteChain", func(t *testing.T) {
		err := manager.ClearAndDeleteChain("CONTAINER_CHAIN")
		if err != nil {
			t.Errorf("ClearAndDeleteChain failed: %v", err)
		}
		exists, _ := mockIpt.ChainExists("filter", "CONTAINER_CHAIN")
		if exists {
			t.Error("Container chain was not deleted")
		}
	})

	t.Run("ChainExists", func(t *testing.T) {
		exists, err := manager.ChainExists("CNI-OUTBOUND")
		if err != nil {
			t.Errorf("ChainExists failed: %v", err)
		}
		if !exists {
			t.Error("CNI-OUTBOUND should exist")
		}

		exists, err = manager.ChainExists("NONEXISTENT_CHAIN")
		if err != nil {
			t.Errorf("ChainExists failed: %v", err)
		}
		if exists {
			t.Error("NONEXISTENT_CHAIN should not exist")
		}
	})

	t.Run("VerifyRules", func(t *testing.T) {
		// Add some rules first
		rules := []OutboundRule{
			{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			{Host: "10.0.0.0/24", Proto: "udp", Port: "53", Action: "ACCEPT"},
		}
		for _, rule := range rules {
			manager.AddRule("CNI-OUTBOUND", rule)
		}

		// Now verify them
		err := manager.VerifyRules("CNI-OUTBOUND", rules)
		if err != nil {
			t.Errorf("VerifyRules failed: %v", err)
		}

		// Try to verify a non-existent rule
		nonExistentRule := OutboundRule{Host: "172.16.0.1", Proto: "tcp", Port: "443", Action: "DROP"}
		err = manager.VerifyRules("CNI-OUTBOUND", []OutboundRule{nonExistentRule})
		if err == nil {
			t.Error("VerifyRules should have failed for non-existent rule")
		}
	})

	t.Run("RemoveJumpRuleByTargetChain", func(t *testing.T) {
		// First, add a jump rule
		manager.AddJumpRule("10.0.0.1", "TARGET_CHAIN")

		// Now remove it
		err := manager.RemoveJumpRuleByTargetChain("TARGET_CHAIN")
		if err != nil {
			t.Errorf("RemoveJumpRuleByTargetChain failed: %v", err)
		}

		rules, _ := mockIpt.List("filter", "CNI-OUTBOUND")
		unexpectedRule := "-A CNI-OUTBOUND -s 10.0.0.1 -j TARGET_CHAIN"
		if slices.Contains(rules, unexpectedRule) {
			t.Error("Jump rule was not removed")
		}

		// Try to remove a non-existent jump rule
		err = manager.RemoveJumpRuleByTargetChain("NONEXISTENT_CHAIN")
		if err == nil {
			t.Error("RemoveJumpRuleByTargetChain should have failed for non-existent chain")
		}
	})
}

func TestNewIPTablesManager(t *testing.T) {
	tests := []struct {
		name           string
		mainChainName  string
		defaultAction  string
		expectError    bool
		errorSubstring string
	}{
		{
			name:          "Valid initialization",
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "DROP",
			expectError:   false,
		},
		{
			name:          "Empty main chain name",
			mainChainName: "",
			defaultAction: "DROP",
			expectError:   false,
		},
		{
			name:          "Empty default action",
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalNewIPTables := newIPTables
			newIPTables = func() (IPTablesWrapper, error) {
				return newMockIPTables(), nil
			}
			// Restore the original function after the test
			defer func() { newIPTables = originalNewIPTables }()

			manager, err := NewIPTablesManager(tt.mainChainName, tt.defaultAction)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error, but got nil")
				} else if tt.errorSubstring != "" && !strings.Contains(err.Error(), tt.errorSubstring) {
					t.Errorf("Expected error containing '%s', but got: %v", tt.errorSubstring, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if manager == nil {
					t.Fatalf("Expected a non-nil IPTablesManager, but got nil")
				}

				// Check if the mainChainName is set correctly
				expectedMainChain := tt.mainChainName
				if expectedMainChain == "" {
					expectedMainChain = "CNI-OUTBOUND" // default value
				}
				if manager.mainChainName != expectedMainChain {
					t.Errorf("Expected mainChainName to be '%s', but got '%s'", expectedMainChain, manager.mainChainName)
				}

				// Check if the defaultAction is set correctly
				expectedDefaultAction := tt.defaultAction
				if expectedDefaultAction == "" {
					expectedDefaultAction = "DROP" // default value
				}
				if manager.defaultAction != expectedDefaultAction {
					t.Errorf("Expected defaultAction to be '%s', but got '%s'", expectedDefaultAction, manager.defaultAction)
				}

				// Check if the iptables instance is initialized
				if manager.ipt == nil {
					t.Errorf("Expected ipt to be initialized, but it's nil")
				}

				// Check if the initialized iptables instance is of type mockIPTables
				_, ok := manager.ipt.(*mockIPTables)
				if !ok {
					t.Errorf("Expected ipt to be of type *mockIPTables, but it's not")
				}
			}
		})
	}
}
