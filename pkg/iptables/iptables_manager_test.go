package iptables

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Mock implementation of iptables.IPTables
type mockIPTables struct {
	chains map[string]bool
	rules  map[string][][]string
}

func newMockIPTables() *mockIPTables {
	return &mockIPTables{
		chains: make(map[string]bool),
		rules:  make(map[string][][]string),
	}
}

func (m *mockIPTables) NewChain(table, chain string) error {
	m.chains[chain] = true
	return nil
}

func (m *mockIPTables) ClearChain(table, chain string) error {
	m.rules[chain] = [][]string{}
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
	m.rules[chain] = append(m.rules[chain], rulespec)
	return nil
}

func (m *mockIPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	newRules := append([][]string{}, m.rules[chain][:pos-1]...)
	newRules = append(newRules, rulespec)
	newRules = append(newRules, m.rules[chain][pos-1:]...)
	m.rules[chain] = newRules
	return nil
}

func (m *mockIPTables) Delete(table, chain string, rulespec ...string) error {
	for i, rule := range m.rules[chain] {
		if reflect.DeepEqual(rule, rulespec) {
			m.rules[chain] = append(m.rules[chain][:i], m.rules[chain][i+1:]...)
			return nil
		}
	}
	return errors.New("rule not found")
}

func (m *mockIPTables) List(table, chain string) ([]string, error) {
	var flatRules []string
	for _, rule := range m.rules[chain] {
		flatRules = append(flatRules, "-A "+chain+" "+strings.Join(rule, " "))
	}
	return flatRules, nil
}

func TestIPTablesManager(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "MAIN_CHAIN",
		defaultAction: "DROP",
	}

	t.Run("EnsureMainChainExists", func(t *testing.T) {
		err := manager.EnsureMainChainExists()
		if err != nil {
			t.Errorf("EnsureMainChainExists failed: %v", err)
		}
		exists, _ := mockIpt.ChainExists("filter", "MAIN_CHAIN")
		if !exists {
			t.Error("Main chain was not created")
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
		if len(rules) != 1 || !strings.Contains(rules[0], "-j DROP") {
			t.Error("Default action was not set for container chain")
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
		rules, _ := mockIpt.List("filter", "MAIN_CHAIN")
		expectedRule := "-A MAIN_CHAIN -s 10.0.0.1 -j CONTAINER_CHAIN"
		if !slices.Contains(rules, expectedRule) {
			t.Errorf("Jump rule was not added correctly. Got %v, want %v", rules, expectedRule)
		}
	})

	t.Run("RemoveJumpRule", func(t *testing.T) {
		err := manager.RemoveJumpRule("10.0.0.1", "CONTAINER_CHAIN")
		if err != nil {
			t.Errorf("RemoveJumpRule failed: %v", err)
		}
		rules, _ := mockIpt.List("filter", "MAIN_CHAIN")
		unexpectedRule := "-A MAIN_CHAIN -s 10.0.0.1 -j CONTAINER_CHAIN"
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
		exists, err := manager.ChainExists("MAIN_CHAIN")
		if err != nil {
			t.Errorf("ChainExists failed: %v", err)
		}
		if !exists {
			t.Error("MAIN_CHAIN should exist")
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
			manager.AddRule("MAIN_CHAIN", rule)
		}

		// Now verify them
		err := manager.VerifyRules("MAIN_CHAIN", rules)
		if err != nil {
			t.Errorf("VerifyRules failed: %v", err)
		}

		// Try to verify a non-existent rule
		nonExistentRule := OutboundRule{Host: "172.16.0.1", Proto: "tcp", Port: "443", Action: "DROP"}
		err = manager.VerifyRules("MAIN_CHAIN", []OutboundRule{nonExistentRule})
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

		rules, _ := mockIpt.List("filter", "MAIN_CHAIN")
		unexpectedRule := "-A MAIN_CHAIN -s 10.0.0.1 -j TARGET_CHAIN"
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
