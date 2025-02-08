package iptables

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"

	"slices"
)

type mockIPTables struct {
	chains       map[string]bool
	rules        map[string][]string
	methodErrors map[string]error
	appendFunc   func(table, chain string, rulespec ...string) error
	insertFunc   func(table, chain string, pos int, rulespec ...string) error
}

func newMockIPTables() *mockIPTables {
	return &mockIPTables{
		chains:       make(map[string]bool),
		rules:        make(map[string][]string),
		methodErrors: make(map[string]error),
	}
}

func (m *mockIPTables) NewChain(table, chain string) error {
	if err := m.methodErrors["NewChain"]; err != nil {
		return err
	}
	m.chains[chain] = true
	return nil
}

func (m *mockIPTables) ChainExists(table, chain string) (bool, error) {
	if err := m.methodErrors["ChainExists"]; err != nil {
		return false, err
	}
	return m.chains[chain], nil
}

func (m *mockIPTables) ClearChain(table, chain string) error {
	if err := m.methodErrors["ClearChain"]; err != nil {
		return err
	}
	if _, exists := m.chains[chain]; !exists {
		return fmt.Errorf("chain %s does not exist", chain)
	}
	m.rules[chain] = []string{}
	return nil
}

func (m *mockIPTables) DeleteChain(table, chain string) error {
	if err := m.methodErrors["DeleteChain"]; err != nil {
		return err
	}
	if _, exists := m.chains[chain]; !exists {
		return fmt.Errorf("chain %s does not exist", chain)
	}
	delete(m.chains, chain)
	delete(m.rules, chain)
	return nil
}

func (m *mockIPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	if m.insertFunc != nil {
		return m.insertFunc(table, chain, pos, rulespec...)
	}
	if err := m.methodErrors["Insert"]; err != nil {
		return err
	}
	// Format rule like real iptables output
	rule := "-A " + chain + " " + strings.Join(rulespec, " ")
	if m.rules[chain] == nil {
		m.rules[chain] = []string{}
	}
	m.rules[chain] = append(m.rules[chain], rule)
	return nil
}

func (m *mockIPTables) Append(table, chain string, rulespec ...string) error {
	if m.appendFunc != nil {
		return m.appendFunc(table, chain, rulespec...)
	}
	if err := m.methodErrors["Append"]; err != nil {
		return err
	}
	// Format rule like real iptables output
	rule := "-A " + chain + " " + strings.Join(rulespec, " ")
	if m.rules[chain] == nil {
		m.rules[chain] = []string{}
	}
	m.rules[chain] = append(m.rules[chain], rule)
	return nil
}

func (m *mockIPTables) Delete(table, chain string, rulespec ...string) error {
	if err := m.methodErrors["Delete"]; err != nil {
		return err
	}
	rule := strings.Join(rulespec, " ")
	for i, r := range m.rules[chain] {
		if strings.Contains(r, rule) {
			m.rules[chain] = append(m.rules[chain][:i], m.rules[chain][i+1:]...)
			return nil
		}
	}
	return nil // Rule not found is not considered an error in iptables
}

func (m *mockIPTables) List(table, chain string) ([]string, error) {
	if err := m.methodErrors["List"]; err != nil {
		return nil, err
	}
	return m.rules[chain], nil
}

// Helper method to set errors for testing
func (m *mockIPTables) SetError(method string, err error) {
	m.methodErrors[method] = err
}

// Helper method to clear errors
func (m *mockIPTables) ClearErrors() {
	m.methodErrors = make(map[string]error)
}

func TestIPTablesManager(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}

	t.Run("EnsureMainChainExists", func(t *testing.T) {
		// First, ensure the chain doesn't exist
		if mockIpt.chains == nil {
			mockIpt.chains = make(map[string]bool)
		}
		mockIpt.chains["CNI-OUTBOUND"] = false

		err := manager.EnsureMainChainExists()
		if err != nil {
			t.Errorf("EnsureMainChainExists failed: %v", err)
		}

		// Check if the main chain was created
		if !mockIpt.chains["CNI-OUTBOUND"] {
			t.Error("Main chain was not created")
		}

		// Check if the jump rule was added to the CNI-FORWARD chain
		forwardRules := mockIpt.rules["CNI-FORWARD"]
		expectedRule := "-j CNI-OUTBOUND"
		found := false
		for _, rule := range forwardRules {
			if strings.Contains(rule, expectedRule) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Jump to CNI-OUTBOUND not added to CNI-FORWARD chain. Rules: %v", forwardRules)
		}

		// Check if the jump rule is at the beginning of the CNI-FORWARD chain
		if len(forwardRules) > 0 && !strings.Contains(forwardRules[0], expectedRule) {
			t.Errorf("Jump to CNI-OUTBOUND is not at the beginning of CNI-FORWARD chain. First rule: %s", forwardRules[0])
		}
	})

	t.Run("CreateContainerChain", func(t *testing.T) {
		mockIpt := newMockIPTables()
		manager := &IPTablesManager{
			ipt:           mockIpt,
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "DROP",
		}

		containerChain := "CONTAINER_CHAIN"
		err := manager.CreateContainerChain(containerChain)
		if err != nil {
			t.Fatalf("CreateContainerChain failed: %v", err)
		}

		// Check if the chain was created
		if !mockIpt.chains[containerChain] {
			t.Error("Container chain was not created")
		}

		// Check the rules in the container chain
		rules := mockIpt.rules[containerChain]
		if len(rules) != 2 {
			t.Errorf("Expected 2 rules in container chain, got %d", len(rules))
		}

		expectedRules := []string{
			"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
			"-j DROP",
		}

		for i, expectedRule := range expectedRules {
			if i >= len(rules) {
				t.Errorf("Missing rule: %s", expectedRule)
				continue
			}
			if !strings.Contains(rules[i], expectedRule) {
				t.Errorf("Rule mismatch. Expected: %s, Got: %s", expectedRule, rules[i])
			}
		}
	})

	t.Run("AddRule", func(t *testing.T) {
		mockIpt := newMockIPTables()
		manager := &IPTablesManager{
			ipt:           mockIpt,
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "DROP",
		}

		chainName := "TEST_CHAIN"
		mockIpt.chains[chainName] = true // Ensure the chain exists

		rule := OutboundRule{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"}
		err := manager.AddRule(chainName, rule)
		if err != nil {
			t.Fatalf("AddRule failed: %v", err)
		}

		// Check if the rule was added to the chain
		rules := mockIpt.rules[chainName]
		if len(rules) == 0 {
			t.Fatal("No rules added to the chain")
		}

		expectedRule := "-d 192.168.1.1 -p tcp --dport 80 -j ACCEPT"
		if !strings.Contains(rules[0], expectedRule) {
			t.Errorf("Rule mismatch. Expected: %s, Got: %s", expectedRule, rules[0])
		}

		// Check if the rule was inserted at the beginning of the chain
		if len(rules) > 1 && strings.Contains(rules[1], expectedRule) {
			t.Error("Rule was not inserted at the beginning of the chain")
		}
	})

	t.Run("AddRuleWithDryRun", func(t *testing.T) {
		testCases := []struct {
			name      string
			rule      OutboundRule
			wantRules []string
		}{
			{
				name: "DROP rule",
				rule: OutboundRule{
					Host:   "192.168.1.1",
					Proto:  "tcp",
					Port:   "80",
					Action: "DROP",
				},
				wantRules: []string{
					`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]"`,
					`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
				},
			},
			{
				name: "ACCEPT rule",
				rule: OutboundRule{
					Host:   "192.168.1.1",
					Proto:  "tcp",
					Port:   "80",
					Action: "ACCEPT",
				},
				wantRules: []string{
					`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]"`,
					`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				mockIpt := newMockIPTables()
				manager := &IPTablesManager{
					ipt:           mockIpt,
					mainChainName: "CNI-OUTBOUND",
					defaultAction: "DROP",
					dryRun:        true,
				}

				err := manager.AddRule("TEST_CHAIN", tc.rule)
				assert.NoError(t, err)

				// Get actual rules
				rules := mockIpt.rules["TEST_CHAIN"]

				// Rules should be in reverse order due to Insert at position 1
				assert.Equal(t, len(tc.wantRules), len(rules), "number of rules")
				for i := range tc.wantRules {
					assert.Equal(t, tc.wantRules[len(tc.wantRules)-1-i], rules[i],
						"rule %d should match", i)
				}
			})
		}
	})

	t.Run("EnsureMainChainExists", func(t *testing.T) {
		err := manager.EnsureMainChainExists()
		if err != nil {
			t.Errorf("EnsureMainChainExists failed: %v", err)
		}
		if !mockIpt.chains["CNI-OUTBOUND"] {
			t.Error("Main chain was not created")
		}
		rules := mockIpt.rules["CNI-FORWARD"]
		expectedRule := "-j CNI-OUTBOUND"
		found := false
		for _, rule := range rules {
			if strings.Contains(rule, expectedRule) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Jump to CNI-OUTBOUND not added to CNI-FORWARD chain. Rules: %v", rules)
		}
	})

	t.Run("CreateContainerChain", func(t *testing.T) {
		err := manager.CreateContainerChain("CONTAINER_CHAIN")
		if err != nil {
			t.Errorf("CreateContainerChain failed: %v", err)
		}
		if !mockIpt.chains["CONTAINER_CHAIN"] {
			t.Error("Container chain was not created")
		}
		rules := mockIpt.rules["CONTAINER_CHAIN"]
		if len(rules) != 2 {
			t.Errorf("Expected 2 rules in container chain, got %d", len(rules))
		}
		expectedRules := []string{
			"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
			"-j DROP",
		}
		for _, expectedRule := range expectedRules {
			found := false
			for _, rule := range rules {
				if strings.Contains(rule, expectedRule) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected rule not found: %s", expectedRule)
			}
		}
	})

	t.Run("AddRule", func(t *testing.T) {
		rule := OutboundRule{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"}
		err := manager.AddRule("CONTAINER_CHAIN", rule)
		if err != nil {
			t.Errorf("AddRule failed: %v", err)
		}
		rules := mockIpt.rules["CONTAINER_CHAIN"]
		expectedRule := "-d 192.168.1.1 -p tcp --dport 80 -j ACCEPT"
		found := false
		for _, r := range rules {
			if strings.Contains(r, expectedRule) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Rule was not added correctly. Got %v, want %v", rules, expectedRule)
		}
	})

	t.Run("AddJumpRule", func(t *testing.T) {
		err := manager.AddJumpRule("10.0.0.1", "CONTAINER_CHAIN")
		if err != nil {
			t.Errorf("AddJumpRule failed: %v", err)
		}
		rules := mockIpt.rules["CNI-OUTBOUND"]
		expectedRule := "-s 10.0.0.1 -j CONTAINER_CHAIN"
		found := false
		for _, r := range rules {
			if strings.Contains(r, expectedRule) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Jump rule was not added correctly. Got %v, want %v", rules, expectedRule)
		}
	})

	t.Run("VerifyRules", func(t *testing.T) {
		mockIpt := newMockIPTables()
		manager := &IPTablesManager{
			ipt:           mockIpt,
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "DROP",
		}

		chainName := "TEST_CHAIN"
		mockIpt.chains[chainName] = true // Ensure the chain exists

		// Add some rules to the chain
		rules := []OutboundRule{
			{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			{Host: "10.0.0.0/24", Proto: "udp", Port: "53", Action: "ACCEPT"},
		}
		for _, rule := range rules {
			ruleSpec := fmt.Sprintf("-A %s -d %s -p %s --dport %s -j %s", chainName, rule.Host, rule.Proto, rule.Port, rule.Action)
			mockIpt.rules[chainName] = append(mockIpt.rules[chainName], ruleSpec)
		}

		// Test verification of existing rules
		err := manager.VerifyRules(chainName, rules)
		if err != nil {
			t.Errorf("VerifyRules failed for existing rules: %v", err)
		}

		// Test verification of non-existent rule
		nonExistentRule := OutboundRule{Host: "172.16.0.1", Proto: "tcp", Port: "443", Action: "DROP"}
		err = manager.VerifyRules(chainName, []OutboundRule{nonExistentRule})
		if err == nil {
			t.Error("VerifyRules should have failed for non-existent rule")
		} else if !strings.Contains(err.Error(), "rule not found") {
			t.Errorf("Unexpected error message: %v", err)
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

	t.Run("CreateContainerChain defaultAction=DROP logDrops=true", func(t *testing.T) {
		// Use a fresh mock so it doesn't conflict with other sub-tests
		mockIpt := newMockIPTables()
		manager := &IPTablesManager{
			ipt:           mockIpt,
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "DROP",
			logDrops:      true, // crucial for default DROP logging
		}

		containerChain := "DEFAULT_DROP_CHAIN"
		err := manager.CreateContainerChain(containerChain)
		if err != nil {
			t.Fatalf("CreateContainerChain failed: %v", err)
		}

		// Check if the chain was actually created
		if !mockIpt.chains[containerChain] {
			t.Error("Container chain was not created")
		}

		// We expect 3 rules now:
		// 1) -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		// 2) -j LOG --log-prefix "[CNI-OUTBOUND-DEFAULT_DROP_CHAIN-DEFAULT-BLOCKED]"
		// 3) -j DROP
		rules := mockIpt.rules[containerChain]
		if len(rules) != 3 {
			t.Fatalf("Expected 3 rules in container chain, got %d: %v", len(rules), rules)
		}

		// 1) Check the RELATED,ESTABLISHED rule
		if !strings.Contains(rules[0], "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT") {
			t.Errorf("Expected first rule to allow RELATED,ESTABLISHED but got: %s", rules[0])
		}

		// 2) Check the default-drop LOG rule
		if !strings.Contains(rules[1], "-j LOG") ||
			!strings.Contains(rules[1], `"[CNI-OUTBOUND-DEFAULT_DROP_CHAIN-DEFAULT-BLOCKED]"`) {
			t.Errorf("Expected second rule to be the default drop logging rule, got: %s", rules[1])
		}

		// 3) Finally the default DROP
		if !strings.Contains(rules[2], "-j DROP") {
			t.Errorf("Expected third rule to be DROP, got: %s", rules[2])
		}
	})

}

func TestNewIPTablesManager(t *testing.T) {
	tests := []struct {
		name           string
		mainChainName  string
		defaultAction  string
		dryRun         bool
		logDrops       bool
		expectError    bool
		errorSubstring string
	}{
		{
			name:          "Valid initialization",
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "DROP",
			dryRun:        false,
			expectError:   false,
		},
		{
			name:          "Valid initialization with dry-run",
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "DROP",
			dryRun:        true,
			expectError:   false,
		},
		{
			name:          "Empty main chain name",
			mainChainName: "",
			defaultAction: "DROP",
			dryRun:        false,
			expectError:   false,
		},
		{
			name:          "Empty main chain name with dry-run",
			mainChainName: "",
			defaultAction: "DROP",
			dryRun:        true,
			expectError:   false,
		},
		{
			name:          "Empty default action",
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "",
			dryRun:        false,
			expectError:   false,
		},
		{
			name:          "Empty default action with dry-run",
			mainChainName: "CNI-OUTBOUND",
			defaultAction: "",
			dryRun:        true,
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

			managerInterface, err := NewIPTablesManager(tt.mainChainName, tt.defaultAction, tt.dryRun, tt.logDrops)
			manager := managerInterface.(*IPTablesManager)

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

				// Check if dryRun is set correctly
				if manager.dryRun != tt.dryRun {
					t.Errorf("Expected dryRun to be '%v', but got '%v'", tt.dryRun, manager.dryRun)
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

func TestNewIPTablesManagerError(t *testing.T) {
	// Override newIPTables to return an error
	originalNewIPTables := newIPTables
	newIPTables = func() (IPTablesWrapper, error) {
		return nil, errors.New("mock iptables initialization error")
	}
	// Restore the original function after the test
	defer func() { newIPTables = originalNewIPTables }()

	_, err := NewIPTablesManager("TEST-CHAIN", "ACCEPT", false, false)
	if err == nil {
		t.Error("Expected an error, but got nil")
	}
	if !strings.Contains(err.Error(), "failed to initialize iptables") {
		t.Errorf("Expected error message to contain 'failed to initialize iptables', but got: %v", err)
	}
}

func TestEnsureMainChainExistsErrors(t *testing.T) {
	testCases := []struct {
		name          string
		errorMethod   string
		expectedError string
	}{
		{
			name:          "ChainExists Error",
			errorMethod:   "ChainExists",
			expectedError: "failed to check main chain existence: mock error",
		},
		{
			name:          "NewChain Error",
			errorMethod:   "NewChain",
			expectedError: "failed to create main chain: mock error",
		},
		{
			name:          "Insert Error",
			errorMethod:   "Insert",
			expectedError: "failed to add jump to main chain in CNI-FORWARD: mock error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			mockIpt.SetError(tc.errorMethod, errors.New("mock error"))

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
			}

			err := manager.EnsureMainChainExists()

			if err == nil {
				t.Error("Expected an error, but got nil")
			} else if err.Error() != tc.expectedError {
				t.Errorf("Expected error message '%s', but got: %s", tc.expectedError, err.Error())
			}

			// Verify the state of the iptables after the error
			if tc.errorMethod == "Insert" {
				if !mockIpt.chains["CNI-OUTBOUND"] {
					t.Error("Expected main chain to be created even if Insert fails")
				}
				if len(mockIpt.rules["CNI-FORWARD"]) > 0 {
					t.Error("Expected no rules in CNI-FORWARD chain after Insert error")
				}
			}

			mockIpt.ClearErrors()
		})
	}
}

func TestCreateContainerChainErrors(t *testing.T) {
	testCases := []struct {
		name          string
		errorMethod   string
		expectedError string
		setupMock     func(*mockIPTables)
		checkState    func(*testing.T, *mockIPTables)
	}{
		{
			name:          "NewChain Error",
			errorMethod:   "NewChain",
			expectedError: "failed to create container chain: mock error",
			setupMock: func(m *mockIPTables) {
				m.SetError("NewChain", errors.New("mock error"))
			},
			checkState: func(t *testing.T, m *mockIPTables) {
				if _, exists := m.chains["TEST-CONTAINER-CHAIN"]; exists {
					t.Error("Expected container chain to not be created after NewChain error")
				}
			},
		},
		{
			name:          "Append RELATED,ESTABLISHED Rule Error",
			errorMethod:   "Append",
			expectedError: "failed to add RELATED,ESTABLISHED rule: mock error",
			setupMock: func(m *mockIPTables) {
				m.SetError("Append", errors.New("mock error"))
			},
			checkState: func(t *testing.T, m *mockIPTables) {
				if _, exists := m.chains["TEST-CONTAINER-CHAIN"]; !exists {
					t.Error("Expected container chain to be created even if first Append fails")
				}
				if len(m.rules["TEST-CONTAINER-CHAIN"]) > 0 {
					t.Error("Expected no rules in container chain after first Append error")
				}
			},
		},
		{
			name:          "Append Default Action Rule Error",
			errorMethod:   "Append",
			expectedError: "failed to set default action for container chain: mock error",
			setupMock: func(m *mockIPTables) {
				callCount := 0
				m.appendFunc = func(table, chain string, rulespec ...string) error {
					callCount++
					if callCount == 2 { // The second Append call is for the default action
						return errors.New("mock error")
					}
					// Simulate successful append for the first call
					rule := strings.Join(rulespec, " ")
					if m.rules[chain] == nil {
						m.rules[chain] = []string{}
					}
					m.rules[chain] = append(m.rules[chain], rule)
					return nil
				}
			},
			checkState: func(t *testing.T, m *mockIPTables) {
				if _, exists := m.chains["TEST-CONTAINER-CHAIN"]; !exists {
					t.Error("Expected container chain to be created")
				}
				if len(m.rules["TEST-CONTAINER-CHAIN"]) != 1 {
					t.Errorf("Expected only RELATED,ESTABLISHED rule in container chain, got %d rules", len(m.rules["TEST-CONTAINER-CHAIN"]))
				}
				expectedRule := "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
				if len(m.rules["TEST-CONTAINER-CHAIN"]) > 0 && !strings.Contains(m.rules["TEST-CONTAINER-CHAIN"][0], expectedRule) {
					t.Errorf("Expected RELATED,ESTABLISHED rule, got: %s", m.rules["TEST-CONTAINER-CHAIN"][0])
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			tc.setupMock(mockIpt)

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
			}

			err := manager.CreateContainerChain("TEST-CONTAINER-CHAIN")

			if err == nil {
				t.Error("Expected an error, but got nil")
			} else if err.Error() != tc.expectedError {
				t.Errorf("Expected error message '%s', but got: %s", tc.expectedError, err.Error())
			}

			// Check the state of the iptables after the error
			tc.checkState(t, mockIpt)

			mockIpt.ClearErrors()
		})
	}
}

func TestClearAndDeleteChainErrors(t *testing.T) {
	testCases := []struct {
		name          string
		errorMethod   string
		expectedError string
		setupMock     func(*mockIPTables)
		checkState    func(*testing.T, *mockIPTables)
	}{
		{
			name:          "ClearChain Error",
			errorMethod:   "ClearChain",
			expectedError: "failed to clear chain TEST-CHAIN: mock error",
			setupMock: func(m *mockIPTables) {
				m.SetError("ClearChain", errors.New("mock error"))
				m.chains["TEST-CHAIN"] = true
				m.rules["TEST-CHAIN"] = []string{"some rule"}
			},
			checkState: func(t *testing.T, m *mockIPTables) {
				if _, exists := m.chains["TEST-CHAIN"]; !exists {
					t.Error("Expected TEST-CHAIN to still exist after ClearChain error")
				}
				if len(m.rules["TEST-CHAIN"]) == 0 {
					t.Error("Expected rules in TEST-CHAIN to remain after ClearChain error")
				}
			},
		},
		{
			name:          "DeleteChain Error",
			errorMethod:   "DeleteChain",
			expectedError: "failed to delete chain TEST-CHAIN: mock error",
			setupMock: func(m *mockIPTables) {
				m.SetError("DeleteChain", errors.New("mock error"))
				m.chains["TEST-CHAIN"] = true
				m.rules["TEST-CHAIN"] = []string{"some rule"}
			},
			checkState: func(t *testing.T, m *mockIPTables) {
				if _, exists := m.chains["TEST-CHAIN"]; !exists {
					t.Error("Expected TEST-CHAIN to still exist after DeleteChain error")
				}
				if len(m.rules["TEST-CHAIN"]) != 0 {
					t.Error("Expected TEST-CHAIN to be cleared even if DeleteChain fails")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			tc.setupMock(mockIpt)

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
			}

			err := manager.ClearAndDeleteChain("TEST-CHAIN")

			if err == nil {
				t.Error("Expected an error, but got nil")
			} else if err.Error() != tc.expectedError {
				t.Errorf("Expected error message '%s', but got: %s", tc.expectedError, err.Error())
			}

			// Check the state of the iptables after the error
			tc.checkState(t, mockIpt)

			mockIpt.ClearErrors()
		})
	}
}

func TestRemoveJumpRuleError(t *testing.T) {
	testCases := []struct {
		name              string
		sourceIP          string
		targetChain       string
		setupMock         func(*mockIPTables)
		expectedError     string
		expectRuleRemoved bool
	}{
		{
			name:        "Delete Error",
			sourceIP:    "10.0.0.1",
			targetChain: "TARGET_CHAIN",
			setupMock: func(m *mockIPTables) {
				m.SetError("Delete", errors.New("mock delete error"))
				// Add the rule that we're trying to remove
				m.Append("filter", "CNI-OUTBOUND", "-s", "10.0.0.1", "-j", "TARGET_CHAIN")
			},
			expectedError:     "failed to remove jump rule: mock delete error",
			expectRuleRemoved: false, // Rule should remain when there's a delete error
		},
		{
			name:        "No Error When Rule Doesn't Exist",
			sourceIP:    "10.0.0.2",
			targetChain: "NONEXISTENT_CHAIN",
			setupMock: func(m *mockIPTables) {
				// Don't add any rules, simulating a situation where the rule doesn't exist
			},
			expectedError:     "",
			expectRuleRemoved: true, // No rule to remove, so it's effectively "removed"
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			tc.setupMock(mockIpt)

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
			}

			err := manager.RemoveJumpRule(tc.sourceIP, tc.targetChain)

			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
			} else {
				if err == nil {
					t.Error("Expected an error, but got nil")
				} else if err.Error() != tc.expectedError {
					t.Errorf("Expected error message '%s', but got: %s", tc.expectedError, err.Error())
				}
			}

			// Check if the rule was removed or not based on our expectation
			rules, _ := mockIpt.List("filter", "CNI-OUTBOUND")
			expectedRule := fmt.Sprintf("-s %s -j %s", tc.sourceIP, tc.targetChain)
			ruleExists := false
			for _, rule := range rules {
				if strings.Contains(rule, expectedRule) {
					ruleExists = true
					break
				}
			}

			if tc.expectRuleRemoved && ruleExists {
				t.Errorf("Expected rule to be removed, but it still exists: %s", expectedRule)
			} else if !tc.expectRuleRemoved && !ruleExists {
				t.Errorf("Expected rule to exist, but it was removed: %s", expectedRule)
			}

			mockIpt.ClearErrors()
		})
	}
}

func TestRemoveJumpRuleByTargetChainError(t *testing.T) {
	testCases := []struct {
		name          string
		targetChain   string
		setupMock     func(*mockIPTables)
		expectedError string
		checkState    func(*testing.T, *mockIPTables)
	}{
		{
			name:        "List Error",
			targetChain: "TARGET_CHAIN",
			setupMock: func(m *mockIPTables) {
				m.SetError("List", errors.New("mock list error"))
				// Add a rule that we're trying to remove
				m.Append("filter", "CNI-OUTBOUND", "-j", "TARGET_CHAIN")
			},
			expectedError: "failed to list rules in main chain: mock list error",
			checkState: func(t *testing.T, m *mockIPTables) {
				rules := m.rules["CNI-OUTBOUND"]
				found := false
				for _, rule := range rules {
					if strings.Contains(rule, "-j TARGET_CHAIN") {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected rule to still exist after List error, but it was removed")
				}
			},
		},
		{
			name:        "No Error When Rule Doesn't Exist",
			targetChain: "NONEXISTENT_CHAIN",
			setupMock: func(m *mockIPTables) {
				// Don't add any rules, simulating a situation where the rule doesn't exist
			},
			expectedError: "jump rule for chain NONEXISTENT_CHAIN not found",
			checkState: func(t *testing.T, m *mockIPTables) {
				// No additional checks needed for this case
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			tc.setupMock(mockIpt)

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
			}

			err := manager.RemoveJumpRuleByTargetChain(tc.targetChain)

			if err == nil {
				t.Error("Expected an error, but got nil")
			} else if err.Error() != tc.expectedError {
				t.Errorf("Expected error message '%s', but got: %s", tc.expectedError, err.Error())
			}

			// Check the state after the operation
			tc.checkState(t, mockIpt)

			mockIpt.ClearErrors()
		})
	}
}

func TestIPTablesManager_ChainExists(t *testing.T) {
	tests := []struct {
		name           string
		chainName      string
		setupMock      func(*mockIPTables)
		expectedResult bool
		expectError    bool
	}{
		{
			name:      "Chain exists",
			chainName: "EXISTING_CHAIN",
			setupMock: func(m *mockIPTables) {
				m.chains["EXISTING_CHAIN"] = true
			},
			expectedResult: true,
			expectError:    false,
		},
		{
			name:      "Chain does not exist",
			chainName: "NONEXISTENT_CHAIN",
			setupMock: func(m *mockIPTables) {
				// Do nothing, chain doesn't exist
			},
			expectedResult: false,
			expectError:    false,
		},
		{
			name:      "Error checking chain existence",
			chainName: "ERROR_CHAIN",
			setupMock: func(m *mockIPTables) {
				m.SetError("ChainExists", errors.New("mock error"))
			},
			expectedResult: false,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			tt.setupMock(mockIpt)

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
			}

			exists, err := manager.ChainExists(tt.chainName)

			if tt.expectError {
				if err == nil {
					t.Error("Expected an error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			if exists != tt.expectedResult {
				t.Errorf("Expected ChainExists to return %v, but got %v", tt.expectedResult, exists)
			}
		})
	}
}

func TestRemoveJumpRuleByTargetChainDeleteError(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}

	// Set up the mock to return an error on Delete
	mockIpt.SetError("Delete", errors.New("mock delete error"))

	// Add a rule that we'll try to remove
	targetChain := "TARGET_CHAIN"
	mockIpt.rules["CNI-OUTBOUND"] = []string{
		"-A CNI-OUTBOUND -s 10.0.0.1 -j TARGET_CHAIN",
	}

	err := manager.RemoveJumpRuleByTargetChain(targetChain)

	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	expectedError := "failed to remove jump rule: mock delete error"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', but got: %s", expectedError, err.Error())
	}

	// Verify that the rule still exists
	if len(mockIpt.rules["CNI-OUTBOUND"]) != 1 {
		t.Error("Expected rule to still exist after Delete error")
	}
}

func TestVerifyRules(t *testing.T) {
	testCases := []struct {
		name          string
		dryRun        bool
		chainName     string
		rules         []OutboundRule
		existingRules []string
		expectedError string
	}{
		{
			name:      "Normal mode - rule exists",
			dryRun:    false,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
			},
			expectedError: "",
		},
		{
			name:      "Normal mode - rule missing",
			dryRun:    false,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.2 -p tcp --dport 80 -j ACCEPT",
			},
			expectedError: "rule not found: -A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
		},
		{
			name:      "Dry run mode - all rules exist",
			dryRun:    true,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "DROP"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix \"[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]\"",
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
				"-A TEST_CHAIN -j LOG --log-prefix [CNI-OUTBOUND-DEFAULT-DROP]",
			},
			expectedError: "",
		},
		{
			name:      "Dry run mode - missing logging rule",
			dryRun:    true,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "DROP"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
				"-A TEST_CHAIN -j LOG --log-prefix [CNI-OUTBOUND-DEFAULT-DROP]",
			},
			expectedError: "rule not found: -A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix \"[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]\"",
		},
		{
			name:      "Dry run mode - missing ACCEPT rule",
			dryRun:    true,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "DROP"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix \"[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]\"",
				"-A TEST_CHAIN -j LOG --log-prefix [CNI-OUTBOUND-DEFAULT-DROP]",
			},
			expectedError: "rule not found: -A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
		},
		{
			name:      "Dry run mode - missing default action logging rule",
			dryRun:    true,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "DROP"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix \"[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]\"",
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
			},
			expectedError: "default action logging rule not found",
		},
		{
			name:      "Dry run mode - multiple rules",
			dryRun:    true,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
				{Host: "192.168.1.2", Proto: "udp", Port: "53", Action: "DROP"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix \"[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]\"",
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
				"-A TEST_CHAIN -d 192.168.1.2 -p udp --dport 53 -j LOG --log-prefix \"[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]\"",
				"-A TEST_CHAIN -d 192.168.1.2 -p udp --dport 53 -j ACCEPT",
				"-A TEST_CHAIN -j LOG --log-prefix [CNI-OUTBOUND-DEFAULT-DROP]",
			},
			expectedError: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			mockIpt.rules[tc.chainName] = tc.existingRules

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
				dryRun:        tc.dryRun,
			}

			err := manager.VerifyRules(tc.chainName, tc.rules)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyRulesListError(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
		dryRun:        false,
	}

	// Set up the mock to return an error on List
	expectedError := errors.New("mock list error")
	mockIpt.SetError("List", expectedError)

	chainName := "TEST_CHAIN"
	rules := []OutboundRule{
		{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
	}

	err := manager.VerifyRules(chainName, rules)

	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	if err.Error() != expectedError.Error() {
		t.Errorf("Expected error '%v', but got: %v", expectedError, err)
	}
}

func TestClearAndDeleteChain(t *testing.T) {
	tests := []struct {
		name          string
		chainName     string
		dryRun        bool
		setupMock     func(*mockIPTables)
		expectedError string
	}{
		{
			name:      "Successful clear and delete",
			chainName: "TEST_CHAIN",
			dryRun:    false,
			setupMock: func(m *mockIPTables) {
				m.chains["TEST_CHAIN"] = true
				m.rules["TEST_CHAIN"] = []string{"some rule"}
			},
			expectedError: "",
		},
		{
			name:      "Successful clear and delete with dry-run",
			chainName: "TEST_CHAIN",
			dryRun:    true,
			setupMock: func(m *mockIPTables) {
				m.chains["TEST_CHAIN"] = true
				m.rules["TEST_CHAIN"] = []string{
					"-d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix [CNI-OUTBOUND-BLOCKED]",
					"-d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
					"-j LOG --log-prefix [CNI-OUTBOUND-DEFAULT-DROP]",
					"-j ACCEPT",
				}
			},
			expectedError: "",
		},
		{
			name:      "Error on clear",
			chainName: "ERROR_CLEAR_CHAIN",
			dryRun:    false,
			setupMock: func(m *mockIPTables) {
				m.chains["ERROR_CLEAR_CHAIN"] = true
				m.SetError("ClearChain", errors.New("mock clear error"))
			},
			expectedError: "failed to clear chain ERROR_CLEAR_CHAIN: mock clear error",
		},
		{
			name:      "Error on clear with dry-run",
			chainName: "ERROR_CLEAR_CHAIN",
			dryRun:    true,
			setupMock: func(m *mockIPTables) {
				m.chains["ERROR_CLEAR_CHAIN"] = true
				m.SetError("ClearChain", errors.New("mock clear error"))
			},
			expectedError: "failed to clear chain ERROR_CLEAR_CHAIN: mock clear error",
		},
		{
			name:      "Error on delete",
			chainName: "ERROR_DELETE_CHAIN",
			dryRun:    false,
			setupMock: func(m *mockIPTables) {
				m.chains["ERROR_DELETE_CHAIN"] = true
				m.SetError("DeleteChain", errors.New("mock delete error"))
			},
			expectedError: "failed to delete chain ERROR_DELETE_CHAIN: mock delete error",
		},
		{
			name:      "Error on delete with dry-run",
			chainName: "ERROR_DELETE_CHAIN",
			dryRun:    true,
			setupMock: func(m *mockIPTables) {
				m.chains["ERROR_DELETE_CHAIN"] = true
				m.SetError("DeleteChain", errors.New("mock delete error"))
			},
			expectedError: "failed to delete chain ERROR_DELETE_CHAIN: mock delete error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			tt.setupMock(mockIpt)

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
				dryRun:        tt.dryRun,
			}

			err := manager.ClearAndDeleteChain(tt.chainName)

			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
				// Verify chain was deleted
				if mockIpt.chains[tt.chainName] {
					t.Error("Chain was not deleted")
				}
				// Verify rules were cleared (including logging rules for dry-run)
				if rules, exists := mockIpt.rules[tt.chainName]; exists && len(rules) > 0 {
					t.Error("Rules were not cleared")
				}
			} else {
				if err == nil {
					t.Error("Expected an error, but got nil")
				} else if err.Error() != tt.expectedError {
					t.Errorf("Expected error '%s', but got: %v", tt.expectedError, err)
				}
			}
		})
	}
}

func TestCreateContainerChainDryRun(t *testing.T) {
	testCases := []struct {
		name          string
		dryRun        bool
		defaultAction string
		mockSetup     func(*mockIPTables)
		expectedRules []string
		expectError   bool
		errorString   string
	}{
		{
			name:          "Dry run mode - successful creation",
			dryRun:        true,
			defaultAction: "DROP",
			mockSetup:     nil,
			expectedRules: []string{
				"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
				"-j LOG --log-prefix \"[CNI-OUTBOUND-TEST-CHAIN-DROP]\"",
				"-j ACCEPT",
			},
			expectError: false,
		},
		{
			name:          "Dry run mode - logging rule append failure",
			dryRun:        true,
			defaultAction: "DROP",
			mockSetup: func(m *mockIPTables) {
				callCount := 0
				m.appendFunc = func(table, chain string, rulespec ...string) error {
					callCount++
					if callCount == 2 && strings.Contains(strings.Join(rulespec, " "), "-j LOG") {
						return fmt.Errorf("mock logging rule error")
					}
					rule := strings.Join(rulespec, " ")
					if m.rules[chain] == nil {
						m.rules[chain] = []string{}
					}
					m.rules[chain] = append(m.rules[chain], rule)
					return nil
				}
			},
			expectError: true,
			errorString: "failed to add default action logging rule: mock logging rule error",
		},
		{
			name:          "Normal mode - successful creation",
			dryRun:        false,
			defaultAction: "DROP",
			mockSetup:     nil,
			expectedRules: []string{
				"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
				"-j DROP",
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			if tc.mockSetup != nil {
				tc.mockSetup(mockIpt)
			}

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: tc.defaultAction,
				dryRun:        tc.dryRun,
			}

			err := manager.CreateContainerChain("TEST-CHAIN")

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorString != "" {
					assert.Equal(t, tc.errorString, err.Error())
				}
				return
			}

			assert.NoError(t, err)
			assert.True(t, mockIpt.chains["TEST-CHAIN"])

			rules := mockIpt.rules["TEST-CHAIN"]
			assert.Equal(t, len(tc.expectedRules), len(rules), "Expected %d rules, got %d", len(tc.expectedRules), len(rules))

			for i, expectedRule := range tc.expectedRules {
				assert.Contains(t, rules[i], expectedRule, "Rule %d doesn't match expected", i)
			}
		})
	}
}

func TestAddRuleLoggingError(t *testing.T) {
	testCases := []struct {
		name          string
		rule          OutboundRule
		mockSetup     func(*mockIPTables)
		expectedError string
		wantRules     []string
	}{
		{
			name: "Dry run mode - logging rule insertion failure",
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			mockSetup: func(m *mockIPTables) {
				// Mock Insert to fail on logging rule
				m.methodErrors["Insert"] = fmt.Errorf("mock logging rule insertion error")
			},
			expectedError: "failed to add rule: mock logging rule insertion error",
		},
		{
			name: "Dry run mode - logging rule insertion success but action rule failure",
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			mockSetup: func(m *mockIPTables) {
				callCount := 0
				m.insertFunc = func(table, chain string, pos int, rulespec ...string) error {
					callCount++
					if callCount == 1 {
						// Let the second rule (ACCEPT) rule succeed
						rule := strings.Join(rulespec, " ")
						if m.rules[chain] == nil {
							m.rules[chain] = []string{}
						}
						m.rules[chain] = append(m.rules[chain], rule)
						return nil
					}
					// Make the first rule (LOG) fail
					return fmt.Errorf("mock action rule error")
				}
			},
			expectedError: "failed to add rule: mock action rule error",
			wantRules: []string{
				`-d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			if tc.mockSetup != nil {
				tc.mockSetup(mockIpt)
			}

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
				dryRun:        true,
			}

			err := manager.AddRule("TEST-CHAIN", tc.rule)

			assert.Error(t, err)
			assert.Equal(t, tc.expectedError, err.Error())

			// If wantRules is specified, verify the rules that got added before the error
			if tc.wantRules != nil {
				rules := mockIpt.rules["TEST-CHAIN"]
				assert.Equal(t, len(tc.wantRules), len(rules), "number of rules added")
				for i, wantRule := range tc.wantRules {
					assert.Contains(t, rules[i], wantRule, "rule %d content", i)
				}
			}
		})
	}
}

func TestBuildRuleSpecs(t *testing.T) {
	testCases := []struct {
		name      string
		dryRun    bool
		logDrops  bool
		chainName string
		host      string
		proto     string
		port      string
		action    string
		wantSpecs [][]string
	}{
		{
			name:      "Dry run mode - DROP action",
			dryRun:    true,
			logDrops:  false,
			chainName: "TEST_CHAIN",
			host:      "192.168.1.1",
			proto:     "tcp",
			port:      "80",
			action:    "DROP",
			wantSpecs: [][]string{
				{"-d", "192.168.1.1", "-p", "tcp", "--dport", "80", "-j", "LOG", "--log-prefix", `"[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]"`},
				{"-d", "192.168.1.1", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"},
			},
		},
		{
			name:      "Normal mode with logDrops - DROP action",
			dryRun:    false,
			logDrops:  true,
			chainName: "TEST_CHAIN",
			host:      "192.168.1.1",
			proto:     "tcp",
			port:      "80",
			action:    "DROP",
			wantSpecs: [][]string{
				{"-d", "192.168.1.1", "-p", "tcp", "--dport", "80", "-j", "LOG", "--log-prefix", `"[CNI-OUTBOUND-TEST_CHAIN-BLOCKED]"`},
				{"-d", "192.168.1.1", "-p", "tcp", "--dport", "80", "-j", "DROP"},
			},
		},
		{
			name:      "Normal mode without logDrops - DROP action",
			dryRun:    false,
			logDrops:  false,
			chainName: "TEST_CHAIN",
			host:      "192.168.1.1",
			proto:     "tcp",
			port:      "80",
			action:    "DROP",
			wantSpecs: [][]string{
				{"-d", "192.168.1.1", "-p", "tcp", "--dport", "80", "-j", "DROP"},
			},
		},
		{
			name:      "Normal mode with logDrops - ACCEPT action (no logging)",
			dryRun:    false,
			logDrops:  true,
			chainName: "TEST_CHAIN",
			host:      "192.168.1.1",
			proto:     "tcp",
			port:      "80",
			action:    "ACCEPT",
			wantSpecs: [][]string{
				{"-d", "192.168.1.1", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manager := &IPTablesManager{
				dryRun:   tc.dryRun,
				logDrops: tc.logDrops,
			}

			gotSpecs := manager.buildRuleSpecs(tc.chainName, tc.host, tc.proto, tc.port, tc.action)

			assert.Equal(t, len(tc.wantSpecs), len(gotSpecs), "number of rule specs")
			for i := range tc.wantSpecs {
				assert.Equal(t, tc.wantSpecs[i], gotSpecs[i], "rule spec %d", i)
			}
		})
	}
}

func TestAddRuleWithLogging(t *testing.T) {
	testCases := []struct {
		name        string
		dryRun      bool
		logDrops    bool
		rule        OutboundRule
		wantRules   []string
		mockSetup   func(*mockIPTables)
		expectError bool
	}{
		{
			name:     "Dry run mode - DROP action",
			dryRun:   true,
			logDrops: false,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			wantRules: []string{
				`-d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-ACCEPTED]"`,
				`-d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
			},
		},
		{
			name:     "Dry run mode - DROP action",
			dryRun:   true,
			logDrops: false,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
		},
		{
			name:     "Normal mode with logDrops - DROP action",
			dryRun:   false,
			logDrops: true,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			wantRules: []string{
				`-d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-BLOCKED]"`,
				`-d 192.168.1.1 -p tcp --dport 80 -j DROP`,
			},
		},
		{
			name:     "Insert failure",
			dryRun:   true,
			logDrops: false,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			mockSetup: func(m *mockIPTables) {
				m.methodErrors["Insert"] = fmt.Errorf("mock insert error")
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			if tc.mockSetup != nil {
				tc.mockSetup(mockIpt)
			}

			manager := &IPTablesManager{
				ipt:      mockIpt,
				dryRun:   tc.dryRun,
				logDrops: tc.logDrops,
			}

			err := manager.AddRule("TEST-CHAIN", tc.rule)
			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Verify rules using buildExpectedRuleLines
			expected := manager.buildExpectedRuleLines("TEST-CHAIN",
				tc.rule.Host, tc.rule.Proto, tc.rule.Port, tc.rule.Action)
			rules := mockIpt.rules["TEST-CHAIN"]

			// Rules should be in reverse order due to Insert at position 1
			assert.Equal(t, len(expected), len(rules), "number of rules")
			for i := range expected {
				assert.Contains(t, rules[len(rules)-1-i], expected[i],
					"rule %d content", i)
			}
		})
	}
}

func TestLogDrops(t *testing.T) {
	testCases := []struct {
		name          string
		dryRun        bool
		logDrops      bool
		rule          OutboundRule
		wantRules     []string
		mockSetup     func(*mockIPTables)
		expectError   bool
		errorContains string
	}{
		{
			name:     "logDrops enabled - DROP action",
			dryRun:   false,
			logDrops: true,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			wantRules: []string{
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-TEST_CHAIN-BLOCKED]"`,
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j DROP`,
			},
		},
		{
			name:     "logDrops enabled - ACCEPT action (no logging)",
			dryRun:   false,
			logDrops: true,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "ACCEPT",
			},
			wantRules: []string{
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
			},
		},
		{
			name:     "logDrops enabled - log rule failure",
			dryRun:   false,
			logDrops: true,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			mockSetup: func(m *mockIPTables) {
				callCount := 0
				m.insertFunc = func(table, chain string, pos int, rulespec ...string) error {
					callCount++
					if callCount == 2 && strings.Contains(strings.Join(rulespec, " "), "LOG") {
						return fmt.Errorf("mock log rule error")
					}
					rule := "-A " + chain + " " + strings.Join(rulespec, " ")
					if m.rules[chain] == nil {
						m.rules[chain] = []string{}
					}
					m.rules[chain] = append(m.rules[chain], rule)
					return nil
				}
			},
			expectError:   true,
			errorContains: "mock log rule error",
		},
		{
			name:     "logDrops disabled - DROP action",
			dryRun:   false,
			logDrops: false,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			wantRules: []string{
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j DROP`,
			},
		},
		{
			name:     "dry run mode overrides logDrops",
			dryRun:   true,
			logDrops: true,
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			wantRules: []string{
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]"`,
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			if tc.mockSetup != nil {
				tc.mockSetup(mockIpt)
			}

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
				dryRun:        tc.dryRun,
				logDrops:      tc.logDrops,
			}

			err := manager.AddRule("TEST_CHAIN", tc.rule)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				return
			}

			assert.NoError(t, err)
			rules := mockIpt.rules["TEST_CHAIN"]
			assert.Equal(t, len(tc.wantRules), len(rules), "number of rules")

			// Rules should be in reverse order due to Insert at position 1
			for i := range tc.wantRules {
				assert.Equal(t, tc.wantRules[len(tc.wantRules)-1-i], rules[i],
					"rule %d content", i)
			}
		})
	}
}

func TestVerifyRulesWithLogDrops(t *testing.T) {
	testCases := []struct {
		name          string
		dryRun        bool
		logDrops      bool
		chainName     string
		rules         []OutboundRule
		existingRules []string
		expectedError string
	}{
		{
			name:      "logDrops enabled - DROP rules exist",
			dryRun:    false,
			logDrops:  true,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "DROP"},
			},
			existingRules: []string{
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-TEST_CHAIN-BLOCKED]"`,
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j DROP`,
			},
		},
		{
			name:      "logDrops enabled - missing log rule",
			dryRun:    false,
			logDrops:  true,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "DROP"},
			},
			existingRules: []string{
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j DROP`,
			},
			expectedError: "rule not found: -A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix \"[CNI-OUTBOUND-TEST_CHAIN-BLOCKED]\"",
		},
		{
			name:      "logDrops enabled - ACCEPT rule (no logging)",
			dryRun:    false,
			logDrops:  true,
			chainName: "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			existingRules: []string{
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			mockIpt.rules[tc.chainName] = tc.existingRules

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
				dryRun:        tc.dryRun,
				logDrops:      tc.logDrops,
			}

			err := manager.VerifyRules(tc.chainName, tc.rules)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLogPrefixesWithChainName(t *testing.T) {
	testCases := []struct {
		name      string
		dryRun    bool
		logDrops  bool
		chainName string
		rule      OutboundRule
		wantRules []string
	}{
		{
			name:      "dry run mode - accepts get chain prefix",
			dryRun:    true,
			logDrops:  false,
			chainName: "TEST_CHAIN",
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			wantRules: []string{
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-TEST_CHAIN-ACCEPTED]"`,
				`-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
			},
		},
		{
			name:      "normal mode with logDrops - blocks get chain prefix",
			dryRun:    false,
			logDrops:  true,
			chainName: "CUSTOM_CHAIN",
			rule: OutboundRule{
				Host:   "192.168.1.1",
				Proto:  "tcp",
				Port:   "80",
				Action: "DROP",
			},
			wantRules: []string{
				`-A CUSTOM_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix "[CNI-OUTBOUND-CUSTOM_CHAIN-BLOCKED]"`,
				`-A CUSTOM_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j DROP`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
				dryRun:        tc.dryRun,
				logDrops:      tc.logDrops,
			}

			err := manager.AddRule(tc.chainName, tc.rule)
			assert.NoError(t, err)

			rules := mockIpt.rules[tc.chainName]
			assert.Equal(t, len(tc.wantRules), len(rules), "number of rules")

			// Rules should be in reverse order due to Insert at position 1
			for i := range tc.wantRules {
				assert.Equal(t, tc.wantRules[len(tc.wantRules)-1-i], rules[i],
					"rule %d content", i)
			}
		})
	}
}

func TestCreateContainerChainWithChainPrefixes(t *testing.T) {
	testCases := []struct {
		name      string
		dryRun    bool
		chainName string
		wantRules []string
	}{
		{
			name:      "dry run mode includes chain name in default action",
			dryRun:    true,
			chainName: "TEST_CHAIN",
			wantRules: []string{
				`-A TEST_CHAIN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`,
				`-A TEST_CHAIN -j LOG --log-prefix "[CNI-OUTBOUND-TEST_CHAIN-DROP]"`,
				`-A TEST_CHAIN -j ACCEPT`,
			},
		},
		{
			name:      "normal mode - no logging",
			dryRun:    false,
			chainName: "TEST_CHAIN",
			wantRules: []string{
				`-A TEST_CHAIN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`,
				`-A TEST_CHAIN -j DROP`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
				dryRun:        tc.dryRun,
			}

			err := manager.CreateContainerChain(tc.chainName)
			assert.NoError(t, err)

			rules := mockIpt.rules[tc.chainName]
			assert.Equal(t, len(tc.wantRules), len(rules), "number of rules")
			for i, wantRule := range tc.wantRules {
				assert.Equal(t, wantRule, rules[i], "rule %d content", i)
			}
		})
	}
}

func TestCreateContainerChain_FailDryRunAcceptAppend(t *testing.T) {
	mockIpt := newMockIPTables()

	callCount := 0
	mockIpt.appendFunc = func(table, chain string, rulespec ...string) error {
		callCount++
		// calls: #1 => RELATED,ESTABLISHED, #2 => LOG, #3 => ACCEPT => fail #3
		if callCount == 3 {
			return fmt.Errorf("mock final accept error")
		}
		return nil
	}

	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
		dryRun:        true,
	}

	err := manager.CreateContainerChain("TEST_DRYRUN_CHAIN")
	if err == nil {
		t.Fatal("Expected an error but got nil")
	}
	expectedErr := "failed to set default action for container chain: mock final accept error"
	if err.Error() != expectedErr {
		t.Errorf("Wanted error %q, got %q", expectedErr, err.Error())
	}
}
