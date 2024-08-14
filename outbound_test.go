package main

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/ncode/cni-outbound/pkg/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type MockIPTablesManager struct {
	mock.Mock
}

func (m *MockIPTablesManager) EnsureMainChainExists() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockIPTablesManager) CreateContainerChain(containerChain string) error {
	args := m.Called(containerChain)
	return args.Error(0)
}

func (m *MockIPTablesManager) AddRule(chainName string, rule iptables.OutboundRule) error {
	args := m.Called(chainName, rule)
	return args.Error(0)
}

func (m *MockIPTablesManager) AddJumpRule(sourceIP, targetChain string) error {
	args := m.Called(sourceIP, targetChain)
	return args.Error(0)
}

func (m *MockIPTablesManager) RemoveJumpRule(sourceIP, targetChain string) error {
	args := m.Called(sourceIP, targetChain)
	return args.Error(0)
}

func (m *MockIPTablesManager) RemoveJumpRuleByTargetChain(targetChain string) error {
	args := m.Called(targetChain)
	return args.Error(0)
}

func (m *MockIPTablesManager) ClearAndDeleteChain(chainName string) error {
	args := m.Called(chainName)
	return args.Error(0)
}

func (m *MockIPTablesManager) ChainExists(chainName string) (bool, error) {
	args := m.Called(chainName)
	return args.Bool(0), args.Error(1)
}

func (m *MockIPTablesManager) VerifyRules(chainName string, rules []iptables.OutboundRule) error {
	args := m.Called(chainName, rules)
	return args.Error(0)
}

func TestParseConfig(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		args           string
		containerID    string
		expectedConfig *PluginConf
		expectedError  string
	}{
		{
			name: "Valid configuration",
			input: `{
				"cniVersion": "0.4.0",
				"name": "test-net",
				"type": "outbound",
				"mainChainName": "TEST-OUTBOUND",
				"defaultAction": "ACCEPT",
				"outboundRules": [
					{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
				]
			}`,
			args:        "",
			containerID: "test-container",
			expectedConfig: &PluginConf{
				NetConf: types.NetConf{
					CNIVersion: "0.4.0",
					Name:       "test-net",
					Type:       "outbound",
				},
				MainChainName: "TEST-OUTBOUND",
				DefaultAction: "ACCEPT",
				OutboundRules: []iptables.OutboundRule{
					{Host: "8.8.8.8", Proto: "udp", Port: "53", Action: "ACCEPT"},
				},
			},
			expectedError: "",
		},
		{
			name: "Invalid JSON",
			input: `{
				"cniVersion": "0.4.0",
				"name": "test-net",
				"type": "outbound",
				"mainChainName": "TEST-OUTBOUND",
				"defaultAction": "ACCEPT",
				"outboundRules": [
					{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
				],
			}`, // Note the trailing comma, which makes this invalid JSON
			args:           "",
			containerID:    "test-container",
			expectedConfig: nil,
			expectedError:  "failed to parse network configuration",
		},
		{
			name: "Error on logging as non-root",
			input: `{
				"cniVersion": "0.4.0",
				"name": "test-net",
				"type": "outbound",
				"mainChainName": "TEST-OUTBOUND",
				"defaultAction": "ACCEPT",
				"logging": { "enable": true, "directory": "" },
				"outboundRules": [
					{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
				]
			}`,
			args:           "",
			containerID:    "test-container",
			expectedConfig: nil,
			expectedError:  "failed to setup logging: failed to open log file",
		},
		{
			name: "Error missing required fields",
			input: `{
				"cniVersion": "0.4.0",
				"name": "test-net",
				"type": "outbound",
				"mainChainName": "TEST-OUTBOUND",
				"defaultAction": "ACCEPT",
				"outboundRules": [
					{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
				],
				"prevResult": {
					"cniVersion": "0.4.0",
					"interfaces": [
						{
							"name": "eth0",
							"mac": "00:11:22:33:44:55"
						}
					],
					"ips": []
				}
			}`,
			args:           "",
			containerID:    "test-container",
			expectedConfig: nil,
			expectedError:  "invalid prevResult structure: missing ips",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := parseConfig([]byte(tc.input), tc.args, tc.containerID)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, conf)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedConfig, conf)
			}
		})
	}
}

func TestCmdAdd(t *testing.T) {
	input := `{
        "cniVersion": "0.4.0",
        "name": "test-net",
        "type": "outbound",
        "mainChainName": "TEST-OUTBOUND",
        "defaultAction": "ACCEPT",
        "outboundRules": [
            {"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
        ],
        "prevResult": {
            "cniVersion": "0.4.0",
            "interfaces": [
                {
                    "name": "eth0",
                    "mac": "00:11:22:33:44:55"
                }
            ],
            "ips": [
                {
                    "version": "4",
                    "interface": 0,
                    "address": "10.0.0.2/24",
                    "gateway": "10.0.0.1"
                }
            ],
            "routes": [
                {
                    "dst": "0.0.0.0/0",
                    "gw": "10.0.0.1"
                }
            ]
        }
    }`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	mockManager := new(MockIPTablesManager)
	mockManager.On("EnsureMainChainExists").Return(nil)
	mockManager.On("CreateContainerChain", mock.Anything).Return(nil)
	mockManager.On("AddRule", mock.Anything, mock.Anything).Return(nil)
	mockManager.On("AddJumpRule", "10.0.0.2", mock.Anything).Return(nil)

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.NoError(t, err)
	mockManager.AssertExpectations(t)
}

func TestCmdAddNoIPs(t *testing.T) {
	input := `{
        "cniVersion": "0.4.0",
        "name": "test-net",
        "type": "outbound",
        "mainChainName": "TEST-OUTBOUND",
        "defaultAction": "ACCEPT",
        "outboundRules": [
            {"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
        ],
        "prevResult": {
            "cniVersion": "0.4.0",
            "interfaces": [
                {
                    "name": "eth0",
                    "mac": "00:11:22:33:44:55"
                }
            ],
            "ips": []
        }
    }`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	mockManager := new(MockIPTablesManager)

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid prevResult structure: missing ips")
}

func TestCmdDel(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT",
		"outboundRules": [
			{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
		]
	}`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	mockManager := new(MockIPTablesManager)
	mockManager.On("RemoveJumpRuleByTargetChain", mock.Anything).Return(nil)
	mockManager.On("ClearAndDeleteChain", mock.Anything).Return(nil)

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdDel(args)
	assert.NoError(t, err)
	mockManager.AssertExpectations(t)
}

func TestCmdCheck(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT",
		"outboundRules": [
			{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
		]
	}`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	mockManager := new(MockIPTablesManager)
	mockManager.On("ChainExists", mock.Anything).Return(true, nil)
	mockManager.On("VerifyRules", mock.Anything, mock.Anything).Return(nil)

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.NoError(t, err)
	mockManager.AssertExpectations(t)
}

func TestCmdDelWithNoIPTablesManager(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT",
		"outboundRules": [
			{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
		]
	}`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	// Override newIPTablesManager to return an error
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return nil, fmt.Errorf("failed to create IPTablesManager")
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdDel(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create IPTablesManager")
}

func TestParseAdditionalRules(t *testing.T) {
	testCases := []struct {
		name          string
		args          string
		expectedRules []iptables.OutboundRule
		expectedError bool
	}{
		{
			name: "Valid additional rules",
			args: "outbound.additional_rules=[{\"host\":\"1.1.1.1\",\"proto\":\"tcp\",\"port\":\"80\",\"action\":\"ACCEPT\"}]",
			expectedRules: []iptables.OutboundRule{
				{Host: "1.1.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			expectedError: false,
		},
		{
			name:          "No additional rules",
			args:          "",
			expectedRules: nil, // Expect nil instead of an empty slice
			expectedError: false,
		},
		{
			name:          "Invalid JSON",
			args:          "outbound.additional_rules=[{\"host\":\"1.1.1.1\",\"proto\":\"tcp\",\"port\":\"80\",\"action\":\"ACCEPT\",}]",
			expectedRules: nil,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := parseAdditionalRules(tc.args, "test-container")
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.expectedRules == nil {
					assert.Nil(t, rules)
				} else {
					assert.Equal(t, tc.expectedRules, rules)
				}
			}
		})
	}
}

func TestGenerateChainName(t *testing.T) {
	chainName := generateChainName("test-net", "test-container")
	assert.NotEmpty(t, chainName)
	assert.Contains(t, chainName, "OUT-")
}

func TestSetupLogging(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "cni-outbound-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Clean up after the test

	testCases := []struct {
		name          string
		config        LogConfig
		expectedDir   string
		expectedError bool
	}{
		{
			name: "Logging disabled",
			config: LogConfig{
				Enable: false,
			},
			expectedDir:   "",
			expectedError: false,
		},
		{
			name: "Logging enabled with custom directory",
			config: LogConfig{
				Enable:    true,
				Directory: filepath.Join(tempDir, "custom"),
			},
			expectedDir:   filepath.Join(tempDir, "custom"),
			expectedError: false,
		},
		{
			name: "Logging enabled with empty directory and fail with lack of permission without root",
			config: LogConfig{
				Enable:    true,
				Directory: "",
			},
			expectedDir:   "/var/log/cni",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &PluginConf{
				Logging: tc.config,
			}

			if tc.config.Enable && tc.config.Directory != "" {
				err := os.MkdirAll(tc.config.Directory, 0755)
				if err != nil {
					t.Fatalf("Failed to create directory: %v", err)
				}
			}

			err := setupLogging(conf)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedDir, conf.Logging.Directory)

				if tc.config.Enable {
					assert.NotNil(t, logger)
					if tc.config.Directory == "" {
						assert.Equal(t, "/var/log/cni", conf.Logging.Directory)
					}
				} else {
					assert.NotNil(t, logger)
				}
			}
		})
	}
}

func TestParseConfigInvalidJSON(t *testing.T) {
	invalidJSON := `{
        "cniVersion": "0.4.0",
        "name": "test-net",
        "type": "outbound",
        "mainChainName": "TEST-OUTBOUND",
        "defaultAction": "ACCEPT",
        "outboundRules": [
            {"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
        ],
    }` // Note the trailing comma, which makes this invalid JSON

	_, err := parseConfig([]byte(invalidJSON), "", "test-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse network configuration")
}

func TestParseConfigMissingFields(t *testing.T) {
	missingFieldsJSON := `{
        "cniVersion": "0.4.0",
        "type": "outbound"
    }`

	conf, err := parseConfig([]byte(missingFieldsJSON), "", "test-container")

	// The function doesn't immediately fail on missing fields
	assert.NoError(t, err)

	// Instead, check that the required fields are empty or have default values
	assert.Empty(t, conf.Name)
	assert.Equal(t, "CNI-OUTBOUND", conf.MainChainName)
	assert.Equal(t, "DROP", conf.DefaultAction)
	assert.Empty(t, conf.OutboundRules)

	// The PrevResult should be nil because it's not provided in the input
	assert.Nil(t, conf.PrevResult)
}

func TestParseAdditionalRulesInvalidJSON(t *testing.T) {
	invalidArgs := "outbound.additional_rules=[{\"host\":\"1.1.1.1\",\"proto\":\"tcp\",\"port\":\"80\",\"action\":\"ACCEPT\",}]" // Note the trailing comma

	_, err := parseAdditionalRules(invalidArgs, "test-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse additional rules from CNI args")
}

func TestCmdAddIPTablesManagerFailure(t *testing.T) {
	input := `{
        "cniVersion": "0.4.0",
        "name": "test-net",
        "type": "outbound",
        "mainChainName": "TEST-OUTBOUND",
        "defaultAction": "ACCEPT",
        "outboundRules": [
            {"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
        ],
        "prevResult": {
            "interfaces": [
                {
                    "name": "eth0",
                    "mac": "00:11:22:33:44:55"
                }
            ],
            "ips": [
                {
                    "address": "10.0.0.2/24",
                    "gateway": "10.0.0.1"
                }
            ]
        }
    }`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	// Override newIPTablesManager to return an error
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return nil, fmt.Errorf("failed to create IPTablesManager")
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create IPTablesManager")
}

func TestCmdDelNoPrevResult(t *testing.T) {
	input := `{
        "cniVersion": "0.4.0",
        "name": "test-net",
        "type": "outbound",
        "mainChainName": "TEST-OUTBOUND",
        "defaultAction": "ACCEPT",
        "outboundRules": [
            {"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
        ]
    }`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	mockManager := new(MockIPTablesManager)
	mockManager.On("RemoveJumpRuleByTargetChain", mock.Anything).Return(nil)
	mockManager.On("ClearAndDeleteChain", mock.Anything).Return(nil)

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdDel(args)
	assert.NoError(t, err)
	mockManager.AssertExpectations(t)
}

func TestCmdCheckChainExistenceFailure(t *testing.T) {
	input := `{
        "cniVersion": "0.4.0",
        "name": "test-net",
        "type": "outbound",
        "mainChainName": "TEST-OUTBOUND",
        "defaultAction": "ACCEPT",
        "outboundRules": [
            {"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
        ]
    }`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	mockManager := new(MockIPTablesManager)
	mockManager.On("ChainExists", mock.Anything).Return(false, nil)

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	mockManager.AssertExpectations(t)
}

func TestParseConfig_PrevResult(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid prevResult",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound",
                "prevResult": {
                    "cniVersion": "0.4.0",
                    "interfaces": [{"name": "eth0", "mac": "00:11:22:33:44:55"}],
                    "ips": [{"version": "4", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}]
                }
            }`,
			expectError: false,
		},
		{
			name: "No prevResult",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound"
            }`,
			expectError: false,
		},
		{
			name: "prevResult with extra key",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound",
                "prevResult": {
                    "cniVersion": "0.4.0",
                    "interfaces": [{"name": "eth0", "mac": "00:11:22:33:44:55"}],
                    "ips": [{"version": "4", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}],
                    "extraKey": "extraValue"
                }
            }`,
			expectError: false,
		},
		{
			name: "Incompatible CNI versions",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound",
                "prevResult": {
                    "cniVersion": "0.1.0",
                    "interfaces": [{"name": "eth0", "mac": "00:11:22:33:44:55"}],
                    "ips": [{"version": "4", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}]
                }
            }`,
			expectError: true,
			errorMsg:    "could not parse prevResult",
		},
		{
			name: "Missing required interfaces in prevResult",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound",
                "prevResult": {
                    "cniVersion": "0.4.0",
                    "ips": [{"version": "4", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}]
                }
            }`,
			expectError: true,
			errorMsg:    "invalid prevResult structure: missing interfaces",
		},
		{
			name: "Missing required ips in prevResult",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound",
                "prevResult": {
                    "cniVersion": "0.4.0",
                    "interfaces": [{"name": "eth0", "mac": "00:11:22:33:44:55"}]
                }
            }`,
			expectError: true,
			errorMsg:    "invalid prevResult structure: missing ips",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, err := parseConfig([]byte(tt.input), "", "test-container")

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, conf)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, conf)

				if strings.Contains(tt.input, "prevResult") {
					assert.NotNil(t, conf.PrevResult, "PrevResult should not be nil")
				} else {
					assert.Nil(t, conf.PrevResult, "PrevResult should be nil")
				}
			}
		})
	}
}
