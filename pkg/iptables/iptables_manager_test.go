package iptables

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"slices"
)

type mockIPTables struct {
	chains       map[string]bool
	rules        map[string][]string
	methodErrors map[string]error
	appendFunc   func(table, chain string, rulespec ...string) error
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

func (m *mockIPTables) Append(table, chain string, rulespec ...string) error {
	if m.appendFunc != nil {
		return m.appendFunc(table, chain, rulespec...)
	}
	if err := m.methodErrors["Append"]; err != nil {
		return err
	}
	rule := strings.Join(rulespec, " ")
	if m.rules[chain] == nil {
		m.rules[chain] = []string{}
	}
	m.rules[chain] = append(m.rules[chain], rule)
	return nil
}

func (m *mockIPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	if err := m.methodErrors["Insert"]; err != nil {
		return err
	}
	rule := strings.Join(rulespec, " ")
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

func TestNewIPTablesManagerError(t *testing.T) {
	// Override newIPTables to return an error
	originalNewIPTables := newIPTables
	newIPTables = func() (IPTablesWrapper, error) {
		return nil, errors.New("mock iptables initialization error")
	}
	// Restore the original function after the test
	defer func() { newIPTables = originalNewIPTables }()

	_, err := NewIPTablesManager("TEST-CHAIN", "ACCEPT")
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
			expectedError: "failed to add jump to main chain in FORWARD: mock error",
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
				if len(mockIpt.rules["FORWARD"]) > 0 {
					t.Error("Expected no rules in FORWARD chain after Insert error")
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
