package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/ncode/cni-outbound/pkg/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

	conf, err := parseConfig([]byte(input), "", "test-container")
	assert.NoError(t, err)
	assert.Equal(t, "TEST-OUTBOUND", conf.MainChainName)
	assert.Equal(t, "ACCEPT", conf.DefaultAction)
	assert.Len(t, conf.OutboundRules, 1)
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

	mockManager := new(MockIPTablesManager)
	mockManager.On("EnsureMainChainExists").Return(nil)
	mockManager.On("CreateContainerChain", mock.Anything).Return(nil)
	mockManager.On("AddRule", mock.Anything, mock.Anything).Return(nil)
	mockManager.On("AddJumpRule", mock.Anything, mock.Anything).Return(nil)

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
				Directory: "/custom/log/dir",
			},
			expectedDir:   "/custom/log/dir",
			expectedError: false,
		},
		{
			name: "Logging enabled with default directory",
			config: LogConfig{
				Enable:    true,
				Directory: "",
			},
			expectedDir:   "/var/log/cni",
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &PluginConf{
				Logging: tc.config,
			}

			err := setupLogging(conf)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedDir, conf.Logging.Directory)
				assert.NotNil(t, logger)

				// Clean up any created log files
				if conf.Logging.Enable {
					os.RemoveAll(conf.Logging.Directory)
				}
			}
		})
	}
}
