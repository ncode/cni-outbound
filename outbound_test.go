package main

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/ncode/cni-outbound/pkg/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"log/slog"
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

func TestParseConfigValidConfiguration(t *testing.T) {
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

	expectedConfig := &PluginConf{
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
	}

	conf, err := parseConfig([]byte(input), "", "test-container")
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig, conf)
}

func TestParseConfigInvalidJSON(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT",
		"outboundRules": [
			{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
		],
	}` // Note the trailing comma

	conf, err := parseConfig([]byte(input), "", "test-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse network configuration")
	assert.Nil(t, conf)
}

func TestParseConfigErrorOnLoggingAsNonRoot(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT",
		"logging": { "enable": true, "directory": "" },
		"outboundRules": [
			{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
		]
	}`

	conf, err := parseConfig([]byte(input), "", "test-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to setup logging: failed to open log file")
	assert.Nil(t, conf)
}

func TestParseConfigErrorMissingRequiredFields(t *testing.T) {
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

	conf, err := parseConfig([]byte(input), "", "test-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid prevResult structure: missing ips")
	assert.Nil(t, conf)
}

func TestParseConfigValidConfigurationWithAdditionalRules(t *testing.T) {
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
	args := `outbound.additional_rules=[{"host":"1.1.1.1","proto":"tcp","port":"80","action":"ACCEPT"}]`

	expectedConfig := &PluginConf{
		NetConf: types.NetConf{
			CNIVersion: "0.4.0",
			Name:       "test-net",
			Type:       "outbound",
		},
		MainChainName: "TEST-OUTBOUND",
		DefaultAction: "ACCEPT",
		OutboundRules: []iptables.OutboundRule{
			{Host: "8.8.8.8", Proto: "udp", Port: "53", Action: "ACCEPT"},
			{Host: "1.1.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
		},
	}

	conf, err := parseConfig([]byte(input), args, "test-container")
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig, conf)
}

func TestParseConfigInvalidAdditionalRules(t *testing.T) {
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
	args := `outbound.additional_rules=[{"host":"1.1.1.1","proto":"tcp","port":"80","action":"ACCEPT",}]` // Note the trailing comma

	conf, err := parseConfig([]byte(input), args, "test-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse additional rules from CNI args")
	assert.Nil(t, conf)
}

func TestParseConfigEmptyAdditionalRules(t *testing.T) {
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
	args := `outbound.additional_rules=[]`

	expectedConfig := &PluginConf{
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
	}

	conf, err := parseConfig([]byte(input), args, "test-container")
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig, conf)
}

func TestParseConfigPrevResultConversionError(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
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
					"gateway": "A.A.A.A"
				}
			]
		}
	}`

	_, err := parseConfig([]byte(input), "", "test-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address: A.A.A.A")
}

func TestParseConfigWithMetadata(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		args             string
		expectedMetadata map[string]string
		expectedRules    []iptables.OutboundRule
		expectError      bool
	}{
		{
			name: "Config metadata only",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound",
                "metadata": {
                    "config_key": "config_value"
                }
            }`,
			args: "",
			expectedMetadata: map[string]string{
				"config_key": "config_value",
			},
			expectedRules: nil,
			expectError:   false,
		},
		{
			name: "Args metadata only",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound"
            }`,
			args: "arg_key=arg_value",
			expectedMetadata: map[string]string{
				"arg_key": "arg_value",
			},
			expectedRules: nil,
			expectError:   false,
		},
		{
			name: "Both metadata sources with override",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound",
                "metadata": {
                    "config_key": "config_value",
                    "override_key": "config_value"
                }
            }`,
			args: "arg_key=arg_value;override_key=arg_value",
			expectedMetadata: map[string]string{
				"config_key":   "config_value",
				"arg_key":      "arg_value",
				"override_key": "arg_value",
			},
			expectedRules: nil,
			expectError:   false,
		},
		{
			name: "Metadata with rules",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound",
                "metadata": {
                    "config_key": "config_value"
                },
                "outboundRules": [
                    {"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
                ]
            }`,
			args: `arg_key=arg_value;outbound.additional_rules=[{"host":"1.1.1.1","proto":"tcp","port":"80","action":"ACCEPT"}]`,
			expectedMetadata: map[string]string{
				"config_key": "config_value",
				"arg_key":    "arg_value",
			},
			expectedRules: []iptables.OutboundRule{
				{Host: "8.8.8.8", Proto: "udp", Port: "53", Action: "ACCEPT"},
				{Host: "1.1.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			expectError: false,
		},
		{
			name: "Invalid additional rules JSON",
			input: `{
                "cniVersion": "0.4.0",
                "name": "test-net",
                "type": "outbound"
            }`,
			args:        `arg_key=arg_value;outbound.additional_rules=[{"host":"1.1.1.1"`,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseConfig([]byte(tc.input), tc.args, "test-container")

			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedMetadata, result.Metadata)

			if tc.expectedRules != nil {
				assert.Equal(t, tc.expectedRules, result.OutboundRules)
			}
		})
	}
}

func TestParseConfigMissingInterfaces(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"prevResult": {
			"cniVersion": "0.4.0",
			"ips": [
				{
					"version": "4",
					"interface": 0,
					"address": "10.0.0.2/24",
					"gateway": "10.0.0.1"
				}
			]
		}
	}`

	_, err := parseConfig([]byte(input), "", "test-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid prevResult structure: missing interfaces")
}

func TestParseConfigDefaultMainChainName(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound"
	}`

	conf, err := parseConfig([]byte(input), "", "test-container")
	assert.NoError(t, err)
	assert.Equal(t, "CNI-OUTBOUND", conf.MainChainName)
}

func TestParseConfigDefaultAction(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound"
	}`

	conf, err := parseConfig([]byte(input), "", "test-container")
	assert.NoError(t, err)
	assert.Equal(t, "DROP", conf.DefaultAction)
}

func TestParseConfigCustomMainChainNameAndDefaultAction(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "CUSTOM-CHAIN",
		"defaultAction": "ACCEPT"
	}`

	conf, err := parseConfig([]byte(input), "", "test-container")
	assert.NoError(t, err)
	assert.Equal(t, "CUSTOM-CHAIN", conf.MainChainName)
	assert.Equal(t, "ACCEPT", conf.DefaultAction)
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

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.NoError(t, err)
	mockManager.AssertExpectations(t)
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

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid prevResult structure: missing ips")
}

func TestCmdAddEnsureMainChainExistsFailure(t *testing.T) {
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
	mockManager.On("EnsureMainChainExists").Return(fmt.Errorf("failed to create main chain"))

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to ensure main chain exists: failed to create main chain")
	mockManager.AssertExpectations(t)
}

func TestCmdAddEnsureCreateContainerChainFailure(t *testing.T) {
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
					"mac": "00:11:22:44:55"
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
	mockManager.On("CreateContainerChain", mock.Anything).Return(fmt.Errorf("failed to create container chain"))

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create container chain")
	mockManager.AssertExpectations(t)
}

func TestCmdAddRuleFailure(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT",
		"outboundRules": [
			{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"},
			{"host": "1.1.1.1", "proto": "tcp", "port": "80", "action": "ACCEPT"}
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
	mockManager.On("AddRule", mock.Anything, mock.MatchedBy(func(rule iptables.OutboundRule) bool {
		return rule.Host == "8.8.8.8"
	})).Return(nil)
	mockManager.On("AddRule", mock.Anything, mock.MatchedBy(func(rule iptables.OutboundRule) bool {
		return rule.Host == "1.1.1.1"
	})).Return(fmt.Errorf("failed to add rule"))

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add rule to container chain: failed to add rule")
	mockManager.AssertExpectations(t)
}

func TestCmdAddNoPrevResult(t *testing.T) {
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
	mockManager.On("EnsureMainChainExists").Return(nil)
	mockManager.On("CreateContainerChain", mock.Anything).Return(nil)
	mockManager.On("AddRule", mock.Anything, mock.Anything).Return(nil)

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no prevResult found")

	// The mock expectations for CreateContainerChain and AddRule should not be met
	// because the function should return early due to missing prevResult
	mockManager.AssertExpectations(t)
}

func TestCmdAddJumpRuleFailure(t *testing.T) {
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
	mockManager.On("AddJumpRule", "10.0.0.2", mock.Anything).Return(fmt.Errorf("failed to add jump rule"))

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdAdd(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add jump rule to main chain: failed to add jump rule")

	mockManager.AssertExpectations(t)
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

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdDel(args)
	assert.NoError(t, err)
	mockManager.AssertExpectations(t)
}

func TestCmdDelParseConfigError(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT",
		"invalidField": true,
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

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdDel(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse network configuration")
}

func TestCmdDelRemoveJumpRuleByTargetChainError(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT"
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
	mockManager.On("RemoveJumpRuleByTargetChain", mock.Anything).Return(fmt.Errorf("failed to remove jump rule"))
	mockManager.On("ClearAndDeleteChain", mock.Anything).Return(nil)

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdDel(args)
	assert.NoError(t, err) // cmdDel should not return an error even if RemoveJumpRuleByTargetChain fails
	mockManager.AssertExpectations(t)
}

func TestCmdDelIPTablesManagerFailure(t *testing.T) {
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

	err := cmdDel(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create IPTablesManager")
}

func TestCmdDelClearAndDeleteChainError(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT"
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
	mockManager.On("ClearAndDeleteChain", mock.Anything).Return(fmt.Errorf("failed to clear and delete chain"))

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdDel(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to clear and delete container chain")
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

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.NoError(t, err)
	mockManager.AssertExpectations(t)
}

func TestCmdCheckWithMetadata(t *testing.T) {
	// Stdin JSON includes some metadata
	input := `{
        "cniVersion": "0.4.0",
        "name": "test-net",
        "type": "outbound",
        "mainChainName": "TEST-OUTBOUND",
        "defaultAction": "ACCEPT",
        "metadata": {
           "test_key": "test_value"
        },
        "outboundRules": [
            {"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
        ]
    }`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod", // More metadata
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	mockManager := new(MockIPTablesManager)
	// Ensure main chain call
	mockManager.On("ChainExists", "TEST-OUTBOUND").Return(true, nil)
	// Container chain call
	mockManager.On("ChainExists", mock.AnythingOfType("string")).Return(true, nil)
	// Verify rules call
	mockManager.On("VerifyRules", mock.Anything, mock.Anything).Return(nil)

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.NoError(t, err)

	// This ensures the manager calls were made as expected
	mockManager.AssertExpectations(t)
}

func TestCmdCheckNewIPTablesManagerFailure(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT"
	}`

	args := &skel.CmdArgs{
		ContainerID: "test-container",
		Netns:       "/var/run/netns/test",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=test;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(input),
	}

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return nil, fmt.Errorf("failed to create IPTablesManager")
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create IPTablesManager")
}

func TestCmdCheckChainExistsFailureForMainChain(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT"
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
	mockManager.On("ChainExists", "TEST-OUTBOUND").Return(false, nil)

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "main chain TEST-OUTBOUND does not exist")
	mockManager.AssertExpectations(t)
}

func TestCmdCheckChainExistsFailure(t *testing.T) {
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
	mockManager.On("ChainExists", "TEST-OUTBOUND").Return(false, fmt.Errorf("mock chain exists error"))

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check if main chain exists: mock chain exists error")
	mockManager.AssertExpectations(t)
}

func TestCmdCheckContainerChainExistsFailure(t *testing.T) {
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
	mockManager.On("ChainExists", "TEST-OUTBOUND").Return(true, nil)

	// Mock the container chain check to fail
	mockManager.On("ChainExists", mock.MatchedBy(func(chainName string) bool {
		return chainName != "TEST-OUTBOUND"
	})).Return(false, fmt.Errorf("mock container chain exists error"))

	// Override newIPTablesManager
	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check if container chain exists: mock container chain exists error")

	mockManager.AssertExpectations(t)
}

func TestCmdCheckChainExistsFailureForContainerChain(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT"
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
	mockManager.On("ChainExists", "TEST-OUTBOUND").Return(true, nil)
	mockManager.On("ChainExists", mock.Anything).Return(false, nil)

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "container chain")
	assert.Contains(t, err.Error(), "does not exist")
	mockManager.AssertExpectations(t)
}

func TestCmdCheckVerifyRulesFailure(t *testing.T) {
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
	mockManager.On("VerifyRules", mock.Anything, mock.Anything).Return(fmt.Errorf("rule verification failed"))

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rule verification failed")
	mockManager.AssertExpectations(t)
}

func TestCmdCheckIPTablesManagerFailure(t *testing.T) {
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

	err := cmdCheck(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create IPTablesManager")
}

func TestCmdCheckParseConfigError(t *testing.T) {
	input := `{
		"cniVersion": "0.4.0",
		"name": "test-net",
		"type": "outbound",
		"mainChainName": "TEST-OUTBOUND",
		"defaultAction": "ACCEPT",
		"invalidField": true,
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

	origNewIPTablesManager := newIPTablesManager
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return mockManager, nil
	}
	defer func() { newIPTablesManager = origNewIPTablesManager }()

	err := cmdCheck(args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse network configuration")
}

func TestSetupLogging(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cni-outbound-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testCases := []struct {
		name        string
		config      LogConfig
		setup       func() error
		expectError bool
		validate    func(t *testing.T, err error)
	}{
		{
			name: "Logging disabled",
			config: LogConfig{
				Enable: false,
			},
			expectError: false,
			validate: func(t *testing.T, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
			},
		},
		{
			name: "Custom directory",
			config: LogConfig{
				Enable:    true,
				Directory: filepath.Join(tempDir, "logs"),
			},
			setup: func() error {
				return os.MkdirAll(filepath.Join(tempDir, "logs"), 0755)
			},
			expectError: false,
			validate: func(t *testing.T, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
			},
		},
		{
			name: "Permission error",
			config: LogConfig{
				Enable:    true,
				Directory: "/root/noaccess",
			},
			expectError: true,
			validate: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to open log file")
			},
		},
		{
			name: "Default directory without permissions",
			config: LogConfig{
				Enable: true,
			},
			expectError: true,
			validate: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to open log file")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				err := tc.setup()
				assert.NoError(t, err)
			}

			conf := &PluginConf{
				Logging: tc.config,
			}

			err := setupLogging(conf)
			tc.validate(t, err)
		})
	}
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
			expectedRules: nil,
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
			rules, _, err := parseArgs(tc.args, "test-container")
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

func TestParseArgsWithLogging(t *testing.T) {
	// Setup logger for testing
	var logBuffer strings.Builder
	logger = slog.New(slog.NewTextHandler(&logBuffer, nil))

	testCases := []struct {
		name              string
		args              string
		expectedRules     []iptables.OutboundRule
		expectedMetadata  map[string]string
		expectError       bool
		expectLogContains []string
	}{
		{
			name:             "Empty args",
			args:             "",
			expectedRules:    nil,
			expectedMetadata: map[string]string{},
			expectError:      false,
			expectLogContains: []string{
				"No additional args provided",
			},
		},
		{
			name: "Valid metadata and rules",
			args: `meta_key=meta_value;outbound.additional_rules=[{"host":"1.1.1.1","proto":"tcp","port":"80","action":"ACCEPT"}]`,
			expectedRules: []iptables.OutboundRule{
				{Host: "1.1.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			expectedMetadata: map[string]string{
				"meta_key": "meta_value",
			},
			expectError: false,
			expectLogContains: []string{
				"Found metadata",
				"Found outbound.additional_rules",
				"Parsed args",
			},
		},
		{
			name:        "Invalid rules JSON",
			args:        `meta_key=meta_value;outbound.additional_rules=[{"host":"1.1.1.1"`,
			expectError: true,
			expectLogContains: []string{
				"Failed to parse additional rules",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logBuffer.Reset()

			rules, metadata, err := parseArgs(tc.args, "test-container")

			if tc.expectError {
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), "failed to parse additional rules from CNI args")
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedRules, rules)
				assert.Equal(t, tc.expectedMetadata, metadata)
			}

			logs := logBuffer.String()
			for _, expectedLog := range tc.expectLogContains {
				assert.Contains(t, logs, expectedLog)
			}
		})
	}
}

func TestGenerateChainName(t *testing.T) {
	chainName := generateChainName("test-net", "test-container")
	assert.NotEmpty(t, chainName)
	assert.Contains(t, chainName, "OUT-")
}

func TestParseArgs(t *testing.T) {
	testCases := []struct {
		name          string
		args          string
		expectedRules []iptables.OutboundRule
		expectedMeta  map[string]string
		expectError   bool
	}{
		{
			name:          "Empty args",
			args:          "",
			expectedRules: nil,
			expectedMeta:  map[string]string{},
			expectError:   false,
		},
		{
			name: "Additional rules only",
			args: `outbound.additional_rules=[{"host":"1.1.1.1","proto":"tcp","port":"80","action":"ACCEPT"}]`,
			expectedRules: []iptables.OutboundRule{
				{Host: "1.1.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			expectedMeta: map[string]string{},
			expectError:  false,
		},
		{
			name:          "Metadata only",
			args:          "K8S_POD_NAME=test-pod;K8S_POD_NAMESPACE=default",
			expectedRules: nil,
			expectedMeta: map[string]string{
				"K8S_POD_NAME":      "test-pod",
				"K8S_POD_NAMESPACE": "default",
			},
			expectError: false,
		},
		{
			name: "Both rules and metadata",
			args: `outbound.additional_rules=[{"host":"1.1.1.1","proto":"tcp","port":"80","action":"ACCEPT"}];K8S_POD_NAME=test-pod`,
			expectedRules: []iptables.OutboundRule{
				{Host: "1.1.1.1", Proto: "tcp", Port: "80", Action: "ACCEPT"},
			},
			expectedMeta: map[string]string{
				"K8S_POD_NAME": "test-pod",
			},
			expectError: false,
		},
		{
			name:        "Invalid additional rules JSON",
			args:        `outbound.additional_rules=[invalid-json]`,
			expectError: true,
		},
		{
			name:          "Skip CNI env vars",
			args:          "CNI_COMMAND=ADD;K8S_POD_NAME=test-pod",
			expectedRules: nil,
			expectedMeta: map[string]string{
				"K8S_POD_NAME": "test-pod",
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rules, meta, err := parseArgs(tc.args, "test-container")

			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRules, rules)
			assert.Equal(t, tc.expectedMeta, meta)
		})
	}
}

func TestGetLogAttrs(t *testing.T) {
	testCases := []struct {
		name     string
		metadata map[string]string
		check    func(t *testing.T, attr slog.Attr)
	}{
		{
			name:     "Empty metadata",
			metadata: nil,
			check: func(t *testing.T, attr slog.Attr) {
				assert.Equal(t, "metadata", attr.Key)
				group := attr.Value.Group()
				assert.Empty(t, group)
			},
		},
		{
			name: "With metadata",
			metadata: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			check: func(t *testing.T, attr slog.Attr) {
				assert.Equal(t, "metadata", attr.Key)
				group := attr.Value.Group()
				assert.Len(t, group, 2)

				values := make(map[string]string)
				for _, a := range group {
					values[a.Key] = a.Value.String()
				}

				assert.Equal(t, "value1", values["key1"])
				assert.Equal(t, "value2", values["key2"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata = tc.metadata
			attr := getLogAttrs()
			tc.check(t, attr)
		})
	}
}

func TestParseConfigComplete(t *testing.T) {
	testCases := []struct {
		name       string
		stdin      []byte
		args       string
		expectFunc func(*testing.T, *PluginConf, error)
	}{
		{
			name: "Full configuration with metadata",
			stdin: []byte(`{
				"cniVersion": "1.0.0",
				"name": "test-net",
				"type": "outbound",
				"mainChainName": "TEST-OUTBOUND",
				"defaultAction": "DROP",
				"dryRun": true,
				"outboundRules": [
					{"host": "8.8.8.8", "proto": "udp", "port": "53", "action": "ACCEPT"}
				],
				"logging": {
					"enable": false
				},
				"metadata": {
					"base": "config"
				}
			}`),
			args: "K8S_POD_NAME=test-pod;outbound.additional_rules=[{\"host\":\"1.1.1.1\",\"proto\":\"tcp\",\"port\":\"80\",\"action\":\"ACCEPT\"}]",
			expectFunc: func(t *testing.T, conf *PluginConf, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, conf)
				assert.Equal(t, "TEST-OUTBOUND", conf.MainChainName)
				assert.Equal(t, "DROP", conf.DefaultAction)
				assert.True(t, conf.DryRun)
				assert.Len(t, conf.OutboundRules, 2)
				assert.Equal(t, "config", conf.Metadata["base"])
				assert.Equal(t, "test-pod", conf.Metadata["K8S_POD_NAME"])
			},
		},
		{
			name: "Minimal configuration",
			stdin: []byte(`{
				"cniVersion": "1.0.0",
				"name": "test-net",
				"type": "outbound"
			}`),
			args: "",
			expectFunc: func(t *testing.T, conf *PluginConf, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, conf)
				assert.Equal(t, "CNI-OUTBOUND", conf.MainChainName)
				assert.Equal(t, "DROP", conf.DefaultAction)
				assert.False(t, conf.DryRun)
				assert.Empty(t, conf.OutboundRules)
				assert.Nil(t, conf.Metadata)
			},
		},
		{
			name:  "Invalid JSON",
			stdin: []byte(`{invalid}`),
			args:  "",
			expectFunc: func(t *testing.T, conf *PluginConf, err error) {
				assert.Error(t, err)
				assert.Nil(t, conf)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := parseConfig(tc.stdin, tc.args, "test-container")
			tc.expectFunc(t, conf, err)
		})
	}
}
