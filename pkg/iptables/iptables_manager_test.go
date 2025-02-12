package iptables

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"strings"
	"testing"
)

// Define the set of characters to use in the random string.
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

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
	// Just append in our mock; real iptables would place it at `pos`
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

// -----------------------------------
// Tests for NewIPTablesManager
// -----------------------------------

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
			defer func() { newIPTables = originalNewIPTables }()

			managerInterface, err := NewIPTablesManager(tt.mainChainName, tt.defaultAction, "", tt.dryRun, tt.logDrops)
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

				// Check chain name
				expectedMainChain := tt.mainChainName
				if expectedMainChain == "" {
					expectedMainChain = "CNI-OUTBOUND"
				}
				assert.Equal(t, expectedMainChain, manager.mainChainName, "mainChainName mismatch")

				// Check default action
				expectedDefaultAction := tt.defaultAction
				if expectedDefaultAction == "" {
					expectedDefaultAction = "DROP"
				}
				assert.Equal(t, expectedDefaultAction, manager.defaultAction, "defaultAction mismatch")

				// Check dryRun
				assert.Equal(t, tt.dryRun, manager.dryRun, "dryRun mismatch")
				// Check if iptables is set
				assert.NotNil(t, manager.ipt, "manager.ipt should not be nil")
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
	defer func() { newIPTables = originalNewIPTables }()

	_, err := NewIPTablesManager("TEST-CHAIN", "ACCEPT", "", false, false)
	if err == nil {
		t.Error("Expected an error, but got nil")
	}
	if !strings.Contains(err.Error(), "failed to initialize iptables") {
		t.Errorf("Expected error message to contain 'failed to initialize iptables', but got: %v", err)
	}
}

// -----------------------------------
// Tests for EnsureMainChainExists
// -----------------------------------

func TestEnsureMainChainExists(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}

	// Ensure chain doesn't exist initially
	mockIpt.chains["CNI-OUTBOUND"] = false
	err := manager.EnsureMainChainExists()
	assert.NoError(t, err, "EnsureMainChainExists should succeed")

	// Check the chain was created
	assert.True(t, mockIpt.chains["CNI-OUTBOUND"], "CNI-OUTBOUND chain not created")

	// Check jump rule in CNI-FORWARD
	forwardRules := mockIpt.rules["CNI-FORWARD"]
	expectedRule := "-j CNI-OUTBOUND"
	found := false
	for _, rule := range forwardRules {
		if strings.Contains(rule, expectedRule) {
			found = true
			break
		}
	}
	assert.True(t, found, "did not find jump to CNI-OUTBOUND in CNI-FORWARD")
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
			assert.Error(t, err)
			assert.Equal(t, tc.expectedError, err.Error())
		})
	}
}

// -----------------------------------
// Tests for CreateContainerChain
// -----------------------------------

func TestCreateContainerChain(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}

	containerChain := "CONTAINER_CHAIN"
	err := manager.CreateContainerChain(containerChain)
	assert.NoError(t, err, "CreateContainerChain failed")

	// Check chain created
	assert.True(t, mockIpt.chains[containerChain], "Container chain not created")

	// Check rules
	rules := mockIpt.rules[containerChain]
	assert.Equal(t, 2, len(rules), "expected 2 rules in container chain")

	expectedRules := []string{
		"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-j DROP",
	}
	for i, expect := range expectedRules {
		assert.Contains(t, rules[i], expect)
	}
}

func TestCreateContainerChainDryRun(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
		dryRun:        true,
	}

	containerChain := "TEST-CHAIN"
	err := manager.CreateContainerChain(containerChain)
	assert.NoError(t, err, "CreateContainerChain in dryRun failed")

	rules := mockIpt.rules[containerChain]
	// Expect 3 rules:
	// 1) RELATED,ESTABLISHED => ACCEPT
	// 2) LOG => prefix "DROP_ "
	// 3) ACCEPT
	assert.Equal(t, 3, len(rules))
	assert.Contains(t, rules[0], "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	assert.Contains(t, rules[1], "-j LOG --log-prefix") // partial check
	assert.Contains(t, rules[1], "DROP_ ")
	assert.Contains(t, rules[2], "-j ACCEPT")
}

func TestCreateContainerChainErrors(t *testing.T) {
	testCases := []struct {
		name          string
		errorMethod   string
		expectedError string
		setupMock     func(*mockIPTables)
	}{
		{
			name:          "NewChain Error",
			errorMethod:   "NewChain",
			expectedError: "failed to create container chain: mock error",
			setupMock: func(m *mockIPTables) {
				m.SetError("NewChain", errors.New("mock error"))
			},
		},
		{
			name:          "Append RELATED,ESTABLISHED Rule Error",
			errorMethod:   "Append",
			expectedError: "failed to add RELATED,ESTABLISHED rule: mock error",
			setupMock: func(m *mockIPTables) {
				m.SetError("Append", errors.New("mock error"))
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
					if callCount == 2 {
						return errors.New("mock error")
					}
					// Simulate success otherwise
					rule := strings.Join(rulespec, " ")
					m.rules[chain] = append(m.rules[chain], rule)
					return nil
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
			assert.Error(t, err)
			assert.Equal(t, tc.expectedError, err.Error())
		})
	}
}

// -----------------------------------
// Tests for AddRule
// -----------------------------------

func TestAddRule(t *testing.T) {
	mockIpt := newMockIPTables()
	chainName := "TEST_CHAIN"
	mockIpt.chains[chainName] = true // ensure chain exists

	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}

	// Basic rule
	rule := OutboundRule{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"}
	err := manager.AddRule(chainName, rule)
	assert.NoError(t, err, "AddRule failed")

	rules := mockIpt.rules[chainName]
	assert.NotEmpty(t, rules, "No rules added to chain")

	// We expect it to be inserted at position 1, so it should appear first in the slice
	expected := "-d 192.168.1.1 -p tcp --dport 80 -j ACCEPT"
	assert.Contains(t, rules[0], expected, "First rule mismatch")
}

// -----------------------------------
// Tests for AddRule in DryRun / Logging
// -----------------------------------

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
				`-d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix DROP_ `,
				`-d 192.168.1.1 -p tcp --dport 80 -j ACCEPT`,
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
				`-d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix DROP_ `,
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
			// Make sure the chain exists
			mockIpt.chains["TEST-CHAIN"] = true

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

			// The code under test calls buildExpectedRuleLines internally
			expected := manager.buildExpectedRuleLines("TEST-CHAIN",
				tc.rule.Host, tc.rule.Proto, tc.rule.Port, tc.rule.Action)
			rules := mockIpt.rules["TEST-CHAIN"]

			// Because Insert happens in reverse order at position 1,
			// the last spec ends up at index 0 in the final slice.
			assert.Equal(t, len(expected), len(rules), "number of rules")

			for i := range expected {
				// We compare in reverse
				assert.Contains(t, rules[len(rules)-1-i], expected[i],
					"rule %d content", i)
			}
		})
	}
}

// -----------------------------------
// Tests for VerifyRules
// -----------------------------------

func TestVerifyRules(t *testing.T) {
	logIdentifier := randString20()
	testCases := []struct {
		name          string
		dryRun        bool
		logIdentifier string
		chainName     string
		rules         []OutboundRule
		existingRules []string
		expectedError string
	}{
		{
			name:          "Normal mode - rule exists",
			dryRun:        false,
			logIdentifier: logIdentifier,
			chainName:     "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
			},
		},
		{
			name:          "Normal mode - rule missing",
			dryRun:        false,
			logIdentifier: logIdentifier,
			chainName:     "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			existingRules: []string{
				"-A TEST_CHAIN -d 192.168.1.2 -p tcp --dport 80 -j ACCEPT",
			},
			expectedError: "rule not found: -A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
		},
		{
			name:          "Dry run mode - all user rules exist, plus default rules exist",
			dryRun:        true,
			logIdentifier: logIdentifier,
			chainName:     "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "DROP"},
			},
			existingRules: []string{
				fmt.Sprintf("-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix DROP_%s ", logIdentifier),
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
				// Default chain logging + accept
				fmt.Sprintf("-A TEST_CHAIN -j LOG --log-prefix DROP_%s ", logIdentifier),
				"-A TEST_CHAIN -j ACCEPT",
			},
		},
		{
			name:          "Dry run mode - missing user logging rule",
			dryRun:        true,
			logIdentifier: logIdentifier,
			chainName:     "TEST_CHAIN",
			rules: []OutboundRule{
				{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "DROP"},
			},
			existingRules: []string{
				// Only the user ACCEPT part, missing the user LOG line
				"-A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j ACCEPT",
				"-A TEST_CHAIN -j ACCEPT",
			},
			// The missing user LOG line triggers "rule not found"
			expectedError: fmt.Sprintf("rule not found: -A TEST_CHAIN -d 192.168.1.1 -p tcp --dport 80 -j LOG --log-prefix DROP_%s ", logIdentifier),
		},
		{
			name:          "Dry run mode - missing default chain logging rule",
			dryRun:        true,
			logIdentifier: logIdentifier,
			chainName:     "TEST_CHAIN",
			rules:         []OutboundRule{}, // no user rules
			existingRules: []string{
				// There's no default chain logging or ACCEPT
				// so the verification should fail the final block
			},
			expectedError: fmt.Sprintf(`default rule not found: -A TEST_CHAIN -j LOG --log-prefix DROP_%s `, logIdentifier),
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
				logIdentifier: tc.logIdentifier,
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

func TestCreateContainerChain_LogDropsNormalMode(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",    // triggers the DROP logic
		logDrops:      true,      // triggers the logDrops branch
		dryRun:        false,     // ensures we *don't* go into the dry-run branch
		logIdentifier: "TESTLOG", // included in the log prefix
	}

	chainName := "CHAIN_LOG_DROPS"
	err := manager.CreateContainerChain(chainName)
	assert.NoError(t, err, "CreateContainerChain should succeed in normal mode with logDrops=true")

	rules := mockIpt.rules[chainName]
	// We expect exactly 3 rules:
	// 1) --ctstate RELATED,ESTABLISHED -j ACCEPT
	// 2) -j LOG --log-prefix "DROP_TESTLOG "
	// 3) -j DROP
	assert.Equal(t, 3, len(rules), "expected 3 rules in the chain")

	// Check each rule in order
	assert.Contains(t, rules[0], "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	assert.Contains(t, rules[1], `-j LOG`)
	// Because your code does: fmt.Sprintf("%s_%s ", m.defaultAction, m.logIdentifier)
	// => "DROP_TESTLOG "
	assert.Contains(t, rules[1], `DROP_TESTLOG `)
	assert.Contains(t, rules[2], `-j DROP`)
}

func TestVerifyRulesListError(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
		dryRun:        false,
	}
	mockIpt.SetError("List", errors.New("mock list error"))

	err := manager.VerifyRules("TEST_CHAIN", []OutboundRule{
		{Host: "192.168.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock list error")
}

// -----------------------------------
// Tests for AddJumpRule, RemoveJumpRule, RemoveJumpRuleByTargetChain, etc.
// -----------------------------------

func TestAddJumpRule(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}
	// Actually create the main chain so we can append
	mockIpt.chains["CNI-OUTBOUND"] = true

	err := manager.AddJumpRule("10.0.0.1", "CONTAINER_CHAIN")
	assert.NoError(t, err)

	rules := mockIpt.rules["CNI-OUTBOUND"]
	assert.Len(t, rules, 1)
	assert.Contains(t, rules[0], "-s 10.0.0.1 -j CONTAINER_CHAIN")
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
			expectRuleRemoved: false,
		},
		{
			name:              "No Error When Rule Doesn't Exist",
			sourceIP:          "10.0.0.2",
			targetChain:       "NONEXISTENT_CHAIN",
			setupMock:         func(m *mockIPTables) {},
			expectedError:     "",
			expectRuleRemoved: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIpt := newMockIPTables()
			mockIpt.chains["CNI-OUTBOUND"] = true
			tc.setupMock(mockIpt)

			manager := &IPTablesManager{
				ipt:           mockIpt,
				mainChainName: "CNI-OUTBOUND",
				defaultAction: "DROP",
			}

			err := manager.RemoveJumpRule(tc.sourceIP, tc.targetChain)

			if tc.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			}

			// Check if the rule was removed or not
			rules, _ := mockIpt.List("filter", "CNI-OUTBOUND")
			expectedRule := fmt.Sprintf("-s %s -j %s", tc.sourceIP, tc.targetChain)
			ruleExists := false
			for _, r := range rules {
				if strings.Contains(r, expectedRule) {
					ruleExists = true
					break
				}
			}
			if tc.expectRuleRemoved && ruleExists {
				t.Errorf("Expected rule to be removed, but it still exists: %s", expectedRule)
			}
			if !tc.expectRuleRemoved && !ruleExists {
				t.Errorf("Expected rule to still exist, but it was removed: %s", expectedRule)
			}
		})
	}
}

func TestRemoveJumpRuleByTargetChain(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}
	mockIpt.chains["CNI-OUTBOUND"] = true

	// Add a jump rule
	mockIpt.rules["CNI-OUTBOUND"] = []string{
		"-A CNI-OUTBOUND -s 10.0.0.1 -j TARGET_CHAIN",
		"-A CNI-OUTBOUND -s 10.0.0.2 -j OTHER_CHAIN",
	}

	// Remove it
	err := manager.RemoveJumpRuleByTargetChain("TARGET_CHAIN")
	assert.NoError(t, err, "RemoveJumpRuleByTargetChain should succeed")

	// Verify removal
	rules := mockIpt.rules["CNI-OUTBOUND"]
	for _, r := range rules {
		assert.False(t, strings.Contains(r, "TARGET_CHAIN"))
	}
}

func TestRemoveJumpRuleByTargetChainError(t *testing.T) {
	mockIpt := newMockIPTables()
	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}
	mockIpt.chains["CNI-OUTBOUND"] = true

	// Add a rule so we have something to remove
	mockIpt.rules["CNI-OUTBOUND"] = []string{
		"-A CNI-OUTBOUND -s 10.0.0.1 -j TARGET_CHAIN",
	}

	// Make Delete return an error
	mockIpt.SetError("Delete", errors.New("mock delete error"))

	err := manager.RemoveJumpRuleByTargetChain("TARGET_CHAIN")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock delete error")

	// Rule should still exist
	rules := mockIpt.rules["CNI-OUTBOUND"]
	assert.Len(t, rules, 1)
}

// -----------------------------------
// Tests for ClearAndDeleteChain
// -----------------------------------

func TestClearAndDeleteChain(t *testing.T) {
	mockIpt := newMockIPTables()
	mockIpt.chains["TEST_CHAIN"] = true
	mockIpt.rules["TEST_CHAIN"] = []string{"some rule"}

	manager := &IPTablesManager{
		ipt:           mockIpt,
		mainChainName: "CNI-OUTBOUND",
		defaultAction: "DROP",
	}

	err := manager.ClearAndDeleteChain("TEST_CHAIN")
	assert.NoError(t, err, "ClearAndDeleteChain should succeed")

	assert.False(t, mockIpt.chains["TEST_CHAIN"], "chain not deleted")
	_, exists := mockIpt.rules["TEST_CHAIN"]
	assert.False(t, exists, "rules for chain not removed")
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
				assert.True(t, m.chains["TEST-CHAIN"], "chain should still exist after ClearChain error")
				assert.NotEmpty(t, m.rules["TEST-CHAIN"], "rules should remain after ClearChain error")
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
				assert.True(t, m.chains["TEST-CHAIN"], "chain should still exist after DeleteChain error")
				assert.Empty(t, m.rules["TEST-CHAIN"], "rules should be cleared even if DeleteChain fails")
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
			assert.Error(t, err)
			assert.Equal(t, tc.expectedError, err.Error())

			tc.checkState(t, mockIpt)
		})
	}
}

// -----------------------------------
// Tests for ChainExists
// -----------------------------------

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
			name:           "Chain does not exist",
			chainName:      "NONEXISTENT_CHAIN",
			setupMock:      func(m *mockIPTables) {},
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
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedResult, exists)
		})
	}
}

func randString20() string {
	const n = 20
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
