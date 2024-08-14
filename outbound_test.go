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

func TestSetupLogging(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cni-outbound-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

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
