package main

import (
	"encoding/json"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/utils"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/ncode/cni-output/pkg/iptables"
)

type PluginConf struct {
	types.NetConf

	MainChainName string                  `json:"mainChainName"`
	DefaultAction string                  `json:"defaultAction"`
	OutboundRules []iptables.OutboundRule `json:"outboundRules"`
}

func generateChainName(netName, containerId string) string {
	return utils.MustFormatChainNameWithPrefix(netName, containerId, "OUT-")
}

func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, fmt.Errorf("could not parse prevResult: %v", err)
	}

	if conf.MainChainName == "" {
		conf.MainChainName = "CNI-OUTBOUND"
	}

	if conf.DefaultAction == "" {
		conf.DefaultAction = "DROP"
	}

	return &conf, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	result, err := current.GetResult(conf.PrevResult)
	if err != nil {
		return fmt.Errorf("failed to convert prevResult: %v", err)
	}

	if len(result.IPs) == 0 {
		return fmt.Errorf("got no container IPs")
	}

	iptManager, err := iptables.NewIPTablesManager(conf.MainChainName, conf.DefaultAction)
	if err != nil {
		return fmt.Errorf("failed to create IPTablesManager: %v", err)
	}

	// Ensure main chain exists
	if err := iptManager.EnsureMainChainExists(); err != nil {
		return fmt.Errorf("failed to ensure main chain exists: %v", err)
	}

	// Create container-specific chain
	containerChain := generateChainName(conf.Name, args.ContainerID)
	if err := iptManager.CreateContainerChain(containerChain); err != nil {
		return fmt.Errorf("failed to create container chain: %v", err)
	}

	// Add rules to container-specific chain
	for _, rule := range conf.OutboundRules {
		if err := iptManager.AddRule(containerChain, rule); err != nil {
			return fmt.Errorf("failed to add rule to container chain: %v", err)
		}
	}

	// Add jump from main chain to container chain
	containerIP := result.IPs[0].Address.IP.String()
	if err := iptManager.AddJumpRule(containerIP, containerChain); err != nil {
		return fmt.Errorf("failed to add jump rule to main chain: %v", err)
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	iptManager, err := iptables.NewIPTablesManager(conf.MainChainName, conf.DefaultAction)
	if err != nil {
		return fmt.Errorf("failed to create IPTablesManager: %v", err)
	}

	containerChain := generateChainName(conf.Name, args.ContainerID)

	// Remove jump rule from main chain (CNI-OUTBOUND)
	if err := iptManager.RemoveJumpRuleByTargetChain(containerChain); err != nil {
		// Log the error but continue, as the container chain might still need cleaning
		fmt.Printf("Warning: failed to remove jump rule from main chain: %v\n", err)
	}

	// Clear and delete container-specific chain
	if err := iptManager.ClearAndDeleteChain(containerChain); err != nil {
		return fmt.Errorf("failed to clear and delete container chain: %v", err)
	}

	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	iptManager, err := iptables.NewIPTablesManager(conf.MainChainName, conf.DefaultAction)
	if err != nil {
		return fmt.Errorf("failed to create IPTablesManager: %v", err)
	}

	// Check if main chain exists
	exists, err := iptManager.ChainExists(conf.MainChainName)
	if err != nil {
		return fmt.Errorf("failed to check if main chain exists: %v", err)
	}
	if !exists {
		return fmt.Errorf("main chain %s does not exist", conf.MainChainName)
	}

	containerChain := generateChainName(conf.Name, args.ContainerID)

	// Check if container chain exists
	exists, err = iptManager.ChainExists(containerChain)
	if err != nil {
		return fmt.Errorf("failed to check if container chain exists: %v", err)
	}
	if !exists {
		return fmt.Errorf("container chain %s does not exist", containerChain)
	}

	// Verify rules in container chain
	if err := iptManager.VerifyRules(containerChain, conf.OutboundRules); err != nil {
		return fmt.Errorf("rule verification failed: %v", err)
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("outbound-firewall"))
}
