package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/utils"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/ncode/cni-outbound/pkg/iptables"
)

// LogConfig holds logging-related settings.
type LogConfig struct {
	Enable    bool   `json:"enable"`
	Directory string `json:"directory"`
}

// PluginConf represents the plugin configuration.
type PluginConf struct {
	types.NetConf

	MainChainName string                  `json:"mainChainName"`
	DefaultAction string                  `json:"defaultAction"`
	OutboundRules []iptables.OutboundRule `json:"outboundRules"`
	Logging       LogConfig               `json:"logging"`
	Metadata      map[string]string       `json:"metadata"`
	DryRun        bool                    `json:"dryRun"`
	LogDrops      bool                    `json:"logDrops"`
}

var (
	// logger is the structured logger instance used throughout the plugin.
	logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	// newIPTablesManager is a function pointer for creating an IPTablesManager (for mocking in tests).
	newIPTablesManager = func(conf *PluginConf) (iptables.Manager, error) {
		return iptables.NewIPTablesManager(conf.MainChainName, conf.DefaultAction, conf.DryRun, conf.LogDrops)
	}
	// metadata is used to store logging metadata (e.g., container ID).
	metadata = map[string]string{}
)

// getLogAttrs aggregates the contents of the global `metadata` map into a slog.Attr.
func getLogAttrs() slog.Attr {
	var attrs []any
	if metadata != nil {
		for k, v := range metadata {
			attrs = append(attrs, slog.String(k, v))
		}
	}
	return slog.Group("metadata", attrs...)
}

// generateChainName creates a short but unique chain name using a prefix and the container ID.
func generateChainName(netName, containerID string) string {
	return utils.MustFormatChainNameWithPrefix(netName, containerID, "OUT-")
}

// parseArgs extracts additional outbound rules and metadata from CNI_ARGS.
func parseArgs(args string) ([]iptables.OutboundRule, map[string]string, error) {
	logger.Log(context.Background(), slog.LevelInfo,
		"Parsing CNI arguments",
		getLogAttrs(),
		slog.String("details", args),
	)

	metadata := make(map[string]string)
	var additionalRules []iptables.OutboundRule

	if args == "" {
		logger.Log(context.Background(), slog.LevelInfo,
			"No additional args provided",
			getLogAttrs(),
		)
		return nil, metadata, nil
	}

	// Skip known CNI env vars that are already available in skel.CmdArgs
	skipKeys := map[string]bool{
		"CNI_COMMAND":     true,
		"CNI_CONTAINERID": true,
		"CNI_PATH":        true,
		"IgnoreUnknown":   true,
	}

	kvs := strings.Split(args, ";")
	for _, kv := range kvs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		if skipKeys[key] {
			continue
		} else if key == "outbound.additional_rules" {
			logger.Log(context.Background(), slog.LevelInfo,
				"Found outbound.additional_rules",
				getLogAttrs(),
				slog.String("rules", value),
			)
			if err := json.Unmarshal([]byte(value), &additionalRules); err != nil {
				logger.Log(context.Background(), slog.LevelError,
					"Failed to parse additional rules",
					getLogAttrs(),
					slog.Any("error", err),
				)
				return nil, nil, fmt.Errorf("failed to parse additional rules from CNI args: %v", err)
			}
		} else {
			metadata[key] = value
			logger.Log(context.Background(), slog.LevelInfo,
				"Found metadata",
				getLogAttrs(),
				slog.String("key", key),
			)
		}
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Parsed args",
		getLogAttrs(),
		slog.Int("ruleCount", len(additionalRules)),
		slog.Int("metadataCount", len(metadata)),
	)

	return additionalRules, metadata, nil
}

// readJSONConfig unmarshals the plugin config from stdin JSON.
func readJSONConfig(stdin []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(stdin, conf); err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to parse network configuration",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}
	return conf, nil
}

// setupPluginLogging configures the logger based on `Logging` fields in the plugin config.
func setupPluginLogging(conf *PluginConf) error {
	if !conf.Logging.Enable {
		return nil
	}

	if conf.Logging.Directory == "" {
		conf.Logging.Directory = "/var/log/cni"
	}

	currentDate := time.Now().Format("2006-01-02")
	logFileName := fmt.Sprintf("%s/outbound-%s.log", strings.TrimSuffix(conf.Logging.Directory, "/"), currentDate)

	file, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	opts := slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
	}
	handler := slog.NewJSONHandler(file, &opts)
	logger = slog.New(handler)
	return nil
}

// parsePrevResult checks if `RawPrevResult` is present and converts it to `current.Result`.
func parsePrevResult(conf *PluginConf) error {
	if conf.RawPrevResult == nil {
		return nil // Nothing to parse
	}
	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Could not parse prevResult",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("could not parse prevResult: %v", err)
	}

	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to convert prevResult to current.Result",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to convert prevResult to current.Result: %v", err)
	}

	if len(result.Interfaces) == 0 {
		return fmt.Errorf("invalid prevResult structure: missing interfaces")
	}
	if len(result.IPs) == 0 {
		return fmt.Errorf("invalid prevResult structure: missing ips")
	}
	conf.PrevResult = result
	return nil
}

// applyAdditionalRules merges any additional rules and metadata from CNI args into the config.
func applyAdditionalRules(conf *PluginConf, additionalRules []iptables.OutboundRule, argsMetadata map[string]string) {
	if len(argsMetadata) > 0 && conf.Metadata == nil {
		conf.Metadata = make(map[string]string)
	}
	if len(additionalRules) > 0 {
		logger.Log(context.Background(), slog.LevelInfo,
			"Appending additional rules",
			getLogAttrs(),
			slog.Int("ruleCount", len(additionalRules)),
		)
		conf.OutboundRules = append(conf.OutboundRules, additionalRules...)
	}
	if len(argsMetadata) > 0 {
		maps.Copy(conf.Metadata, argsMetadata)
		maps.Copy(metadata, conf.Metadata)
	}
}

// parseConfig is the main entry for reading stdin config + CNI_ARGS.
// It delegates to smaller helper functions for clarity.
func parseConfig(stdin []byte, args, containerID string) (*PluginConf, error) {
	additionalRules, argsMetadata, err := parseArgs(args)
	if err != nil {
		return nil, err
	}

	conf, err := readJSONConfig(stdin)
	if err != nil {
		return nil, err
	}

	if err := setupPluginLogging(conf); err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to setup logging",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to setup logging: %v", err)
	}

	if conf.DryRun {
		logger.Log(context.Background(), slog.LevelInfo,
			"Dry run mode enabled - traffic will be logged but not blocked",
			getLogAttrs(),
		)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Parsing configuration",
		getLogAttrs(),
	)

	if err := parsePrevResult(conf); err != nil {
		return nil, err
	}

	applyAdditionalRules(conf, additionalRules, argsMetadata)

	// Set defaults if needed
	if conf.MainChainName == "" {
		logger.Log(context.Background(), slog.LevelInfo,
			"Using default MainChainName: CNI-OUTBOUND",
			getLogAttrs(),
		)
		conf.MainChainName = "CNI-OUTBOUND"
	}
	if conf.DefaultAction == "" {
		logger.Log(context.Background(), slog.LevelInfo,
			"Using default DefaultAction: DROP",
			getLogAttrs(),
		)
		conf.DefaultAction = "DROP"
	}

	return conf, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	metadata["component"] = "CNI-Outbound"
	metadata["containerID"] = args.ContainerID

	conf, err := parseConfig(args.StdinData, args.Args, args.ContainerID)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to parse config",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return err
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"CNI ADD called",
		getLogAttrs(),
	)

	logger.Log(context.Background(), slog.LevelInfo,
		"Creating IPTablesManager",
		getLogAttrs(),
	)

	iptManager, err := newIPTablesManager(conf)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to create IPTablesManager",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to create IPTablesManager: %v", err)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Ensuring main chain exists",
		getLogAttrs(),
	)

	if err := iptManager.EnsureMainChainExists(); err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to ensure main chain exists",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to ensure main chain exists: %v", err)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Creating container chain",
		getLogAttrs(),
	)

	containerChain := generateChainName(conf.Name, args.ContainerID)
	if err := iptManager.CreateContainerChain(containerChain); err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to create container chain",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to create container chain: %v", err)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Adding rules to container chain",
	)

	for _, rule := range conf.OutboundRules {
		logger.Log(context.Background(), slog.LevelInfo,
			"Adding rule",
			getLogAttrs(),
			slog.Any("rule", rule),
		)
		if err := iptManager.AddRule(containerChain, rule); err != nil {
			logger.Log(context.Background(), slog.LevelError,
				"Failed to add rule to container chain",
				getLogAttrs(),
				slog.Any("error", err),
				slog.Any("rule", rule),
			)
			return fmt.Errorf("failed to add rule to container chain: %v", err)
		}
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Adding jump rule(s) to main chain for each IPv4",
		getLogAttrs(),
	)

	// We must have at least one IP from prevResult
	if conf.PrevResult == nil {
		return fmt.Errorf("no prevResult found")
	}
	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to parse prevResult",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to parse prevResult: %v", err)
	}

	var foundAnyIPv4 bool
	for _, ipInfo := range result.IPs {
		ipv4Addr := ipInfo.Address.IP.To4()
		if ipv4Addr == nil {
			continue
		}
		foundAnyIPv4 = true
		containerIP := ipv4Addr.String()

		logger.Log(context.Background(), slog.LevelInfo,
			"Container IPv4 obtained",
			getLogAttrs(),
			slog.String("ip", containerIP),
		)

		if err := iptManager.AddJumpRule(containerIP, containerChain); err != nil {
			logger.Log(context.Background(), slog.LevelError,
				"Failed to add jump rule to main chain",
				getLogAttrs(),
				slog.Any("error", err),
			)
			return fmt.Errorf("failed to add jump rule to main chain: %v", err)
		}
	}

	if !foundAnyIPv4 {
		logger.Log(context.Background(), slog.LevelError,
			"No IPv4 addresses found in prevResult",
			getLogAttrs(),
		)
		return fmt.Errorf("no IPv4 addresses found in prevResult")
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"CNI ADD completed successfully",
		getLogAttrs(),
	)
	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	metadata["component"] = "CNI-Outbound"
	metadata["containerID"] = args.ContainerID

	conf, err := parseConfig(args.StdinData, args.Args, args.ContainerID)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to parse config",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return err
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"CNI DEL called",
		getLogAttrs(),
	)

	logger.Log(context.Background(), slog.LevelInfo,
		"Creating IPTablesManager",
		getLogAttrs(),
	)

	iptManager, err := newIPTablesManager(conf)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to create IPTablesManager",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to create IPTablesManager: %v", err)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Removing container chain",
		getLogAttrs(),
	)

	containerChain := generateChainName(conf.Name, args.ContainerID)
	if err := iptManager.RemoveJumpRuleByTargetChain(containerChain); err != nil {
		logger.Log(context.Background(), slog.LevelWarn,
			"Failed to remove jump rule from main chain",
			getLogAttrs(),
			slog.Any("error", err),
		)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Clearing and deleting container chain",
		getLogAttrs(),
	)

	if err := iptManager.ClearAndDeleteChain(containerChain); err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to clear and delete container chain",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to clear and delete container chain: %v", err)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"CNI DEL completed successfully",
		getLogAttrs(),
	)
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	metadata["component"] = "CNI-Outbound"
	metadata["containerID"] = args.ContainerID

	conf, err := parseConfig(args.StdinData, args.Args, args.ContainerID)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to parse config",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return err
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"CNI CHECK called",
		getLogAttrs(),
	)

	logger.Log(context.Background(), slog.LevelInfo,
		"Creating IPTablesManager",
		getLogAttrs(),
	)

	iptManager, err := newIPTablesManager(conf)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to create IPTablesManager",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to create IPTablesManager: %v", err)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Checking if main chain exists",
		getLogAttrs(),
	)

	exists, err := iptManager.ChainExists(conf.MainChainName)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to check if main chain exists",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to check if main chain exists: %v", err)
	}
	if !exists {
		logger.Log(context.Background(), slog.LevelError,
			"Main chain does not exist",
			getLogAttrs(),
			slog.String("chain", conf.MainChainName),
		)
		return fmt.Errorf("main chain %s does not exist", conf.MainChainName)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Checking container chain",
		getLogAttrs(),
	)

	containerChain := generateChainName(conf.Name, args.ContainerID)
	exists, err = iptManager.ChainExists(containerChain)
	if err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Failed to check if container chain exists",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to check if container chain exists: %v", err)
	}
	if !exists {
		logger.Log(context.Background(), slog.LevelError,
			"Container chain does not exist",
			getLogAttrs(),
			slog.String("chain", containerChain),
		)
		return fmt.Errorf("container chain %s does not exist", containerChain)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"Verifying rules in container chain",
		getLogAttrs(),
	)

	if err := iptManager.VerifyRules(containerChain, conf.OutboundRules); err != nil {
		logger.Log(context.Background(), slog.LevelError,
			"Rule verification failed",
			getLogAttrs(),
			slog.Any("error", err),
		)
		return fmt.Errorf("rule verification failed: %v", err)
	}

	logger.Log(context.Background(), slog.LevelInfo,
		"CNI CHECK completed successfully",
		getLogAttrs(),
	)
	return nil
}

// main is the plugin entry point.
func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("outbound"))
}
