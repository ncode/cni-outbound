package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/containernetworking/plugins/pkg/utils"
	"io"
	"log/slog"
	"maps"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
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
	newIPTablesManager = func(conf *PluginConf, logIdentifier string) (iptables.Manager, error) {
		return iptables.NewIPTablesManager(conf.MainChainName, conf.DefaultAction, logIdentifier, conf.DryRun, conf.LogDrops)
	}
	// metadata is used to store logging metadata (e.g., container ID).
	metadata = map[string]string{}
)

// logAndWrap logs an error and returns a formatted error
func logAndWrap(ctx context.Context, msg string, err error) error {
	// This is kinda weird, but I could not find a better way to capitalize only first word of a multi-word sentence to log
	runes := []rune(msg)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	logger.Log(ctx, slog.LevelError, string(runes), getLogAttrs(), slog.Any("error", err))
	return fmt.Errorf("%s: %v", msg, err)
}

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

// parseArgs extracts additional outbound rules and metadata from CNI_ARGS.
func parseArgs(ctx context.Context, args string) ([]iptables.OutboundRule, map[string]string, error) {
	logger.Log(ctx, slog.LevelInfo,
		"Parsing CNI arguments", getLogAttrs(), slog.String("details", args))

	metadata := make(map[string]string)
	var additionalRules []iptables.OutboundRule

	if args == "" {
		logger.Log(ctx, slog.LevelInfo, "No additional args provided", getLogAttrs())
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
			logger.Log(ctx, slog.LevelInfo,
				"Found outbound.additional_rules", getLogAttrs(), slog.String("rules", value))
			if err := json.Unmarshal([]byte(value), &additionalRules); err != nil {
				return nil, nil, logAndWrap(ctx, "failed to parse additional rules from CNI args", err)
			}
		} else {
			metadata[key] = value
			logger.Log(ctx, slog.LevelInfo,
				"Found metadata", getLogAttrs(), slog.String("key", key))
		}
	}

	logger.Log(ctx, slog.LevelInfo,
		"Parsed args", getLogAttrs(),
		slog.Int("ruleCount", len(additionalRules)),
		slog.Int("metadataCount", len(metadata)))

	return additionalRules, metadata, nil
}

// readJSONConfig unmarshals the plugin config from stdin JSON.
func readJSONConfig(ctx context.Context, stdin []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(stdin, conf); err != nil {
		return nil, logAndWrap(ctx, "failed to parse network configuration", err)
	}
	return conf, nil
}

// setupPluginLogging configures the logger based on `Logging` fields in the plugin config.
func setupPluginLogging(ctx context.Context, conf *PluginConf) error {
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
func parsePrevResult(ctx context.Context, conf *PluginConf) error {
	if conf.RawPrevResult == nil {
		return nil // Nothing to parse
	}
	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return logAndWrap(ctx, "could not parse prevResult", err)
	}

	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return logAndWrap(ctx, "failed to convert prevResult to current.Result", err)
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

// applyDefaults sets default values for the configuration
func applyDefaults(ctx context.Context, conf *PluginConf) {
	if conf.MainChainName == "" {
		logger.Log(ctx, slog.LevelInfo,
			"Using default MainChainName: CNI-OUTBOUND", getLogAttrs())
		conf.MainChainName = "CNI-OUTBOUND"
	}
	if conf.DefaultAction == "" {
		logger.Log(ctx, slog.LevelInfo,
			"Using default DefaultAction: DROP", getLogAttrs())
		conf.DefaultAction = "DROP"
	}

	if conf.DryRun {
		logger.Log(ctx, slog.LevelInfo,
			"Dry run mode enabled - traffic will be logged but not blocked", getLogAttrs())
	}
}

// mergeMetadata merges metadata from different sources into a single map
func mergeMetadata(conf *PluginConf, argsMetadata map[string]string) {
	if len(argsMetadata) > 0 {
		if conf.Metadata == nil {
			conf.Metadata = make(map[string]string)
		}
		maps.Copy(conf.Metadata, argsMetadata)
		maps.Copy(metadata, conf.Metadata)
	}
}

// parseConfig is the main entry for reading stdin config + CNI_ARGS.
// It delegates to smaller helper functions for clarity.
func parseConfig(stdin []byte, args, containerID string) (*PluginConf, error) {
	// Create a context for this operation
	ctx := context.Background()

	// Initialize base metadata
	metadata["component"] = "CNI-Outbound"
	metadata["containerID"] = containerID

	// Step 1: Parse the JSON config
	conf, err := readJSONConfig(ctx, stdin)
	if err != nil {
		return nil, err
	}

	// Step 2: Parse additional rules from args
	additionalRules, argsMetadata, err := parseArgs(ctx, args)
	if err != nil {
		return nil, err
	}

	// Step 3: Set up logging
	if err := setupPluginLogging(ctx, conf); err != nil {
		return nil, logAndWrap(ctx, "failed to setup logging", err)
	}

	// Step 4: Parse previous result
	if err := parsePrevResult(ctx, conf); err != nil {
		return nil, err
	}

	// Step 5: Apply additional rules
	if len(additionalRules) > 0 {
		logger.Log(ctx, slog.LevelInfo,
			"Appending additional rules", getLogAttrs(),
			slog.Int("ruleCount", len(additionalRules)))
		conf.OutboundRules = append(conf.OutboundRules, additionalRules...)
	}

	// Step 6: Merge metadata
	mergeMetadata(conf, argsMetadata)

	// Step 7: Apply defaults
	applyDefaults(ctx, conf)

	return conf, nil
}

// setupIPTables creates and configures an iptables manager for the container
func setupIPTables(ctx context.Context, conf *PluginConf, containerId, ifName string) (iptables.Manager, string, error) {
	containerChain := utils.MustFormatChainNameWithPrefix(conf.Name, containerId, "OUT-")
	logIdentifier := strings.Replace(containerChain, "CNI-OUT-", "", -1)

	// Create IPTablesManager
	iptManager, err := newIPTablesManager(conf, logIdentifier)
	if err != nil {
		return nil, "", logAndWrap(ctx, "failed to create IPTablesManager", err)
	}

	return iptManager, containerChain, nil
}

// setupContainerChain creates the container chain and add rules to it
func setupContainerChain(ctx context.Context, iptManager iptables.Manager, chainName string, rules []iptables.OutboundRule) error {
	// Ensure main chain exists
	logger.Log(ctx, slog.LevelInfo, "Ensuring main chain exists", getLogAttrs())
	if err := iptManager.EnsureMainChainExists(); err != nil {
		return logAndWrap(ctx, "failed to ensure main chain exists", err)
	}

	// Create container chain
	logger.Log(ctx, slog.LevelInfo, "Creating container chain", getLogAttrs())
	if err := iptManager.CreateContainerChain(chainName); err != nil {
		return logAndWrap(ctx, "failed to create container chain", err)
	}

	// Add rules to container chain
	logger.Log(ctx, slog.LevelInfo, "Adding rules to container chain", getLogAttrs())
	for _, rule := range rules {
		logger.Log(ctx, slog.LevelInfo, "Adding rule", getLogAttrs(), slog.Any("rule", rule))
		if err := iptManager.AddRule(chainName, rule); err != nil {
			return logAndWrap(ctx, "failed to add rule to container chain", err)
		}
	}

	return nil
}

// addJumpRulesForIPs adds jump rules for each IPv4 address in the result
func addJumpRulesForIPs(ctx context.Context, conf *PluginConf, iptManager iptables.Manager, containerChain string) error {
	if conf.PrevResult == nil {
		return fmt.Errorf("no prevResult found")
	}

	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return logAndWrap(ctx, "failed to parse prevResult", err)
	}

	var foundAnyIPv4 bool
	for _, ipInfo := range result.IPs {
		ipv4Addr := ipInfo.Address.IP.To4()
		if ipv4Addr == nil {
			continue
		}
		foundAnyIPv4 = true
		containerIP := ipv4Addr.String()

		logger.Log(ctx, slog.LevelInfo,
			"Container IPv4 obtained", getLogAttrs(), slog.String("ip", containerIP))

		if err := iptManager.AddJumpRule(containerIP, containerChain); err != nil {
			return logAndWrap(ctx, "failed to add jump rule to main chain", err)
		}
	}

	if !foundAnyIPv4 {
		logger.Log(ctx, slog.LevelError,
			"No IPv4 addresses found in prevResult", getLogAttrs())
		return fmt.Errorf("no IPv4 addresses found in prevResult")
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	// Parse configuration
	conf, err := parseConfig(args.StdinData, args.Args, args.ContainerID)
	if err != nil {
		return err
	}

	// Create a context for this operation
	ctx := context.Background()

	logger.Log(ctx, slog.LevelInfo, "CNI ADD called", getLogAttrs())

	// Setup iptables
	iptManager, containerChain, err := setupIPTables(ctx, conf, args.ContainerID, args.IfName)
	if err != nil {
		return err
	}

	// Create container chain and add rules
	if err := setupContainerChain(ctx, iptManager, containerChain, conf.OutboundRules); err != nil {
		return err
	}

	// Add jump rules for IPs
	if err := addJumpRulesForIPs(ctx, conf, iptManager, containerChain); err != nil {
		return err
	}

	logger.Log(ctx, slog.LevelInfo, "CNI ADD completed successfully", getLogAttrs())

	result, _ := current.NewResultFromResult(conf.PrevResult)
	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// Parse configuration
	conf, err := parseConfig(args.StdinData, args.Args, args.ContainerID)
	if err != nil {
		return err
	}

	// Create a context for this operation
	ctx := context.Background()

	logger.Log(ctx, slog.LevelInfo, "CNI DEL called", getLogAttrs())

	// Setup iptables
	iptManager, containerChain, err := setupIPTables(ctx, conf, args.ContainerID, args.IfName)
	if err != nil {
		return err
	}

	// Remove jump rule
	logger.Log(ctx, slog.LevelInfo, "Removing container chain", getLogAttrs())
	if err := iptManager.RemoveJumpRuleByTargetChain(containerChain); err != nil {
		logger.Log(ctx, slog.LevelWarn,
			"Failed to remove jump rule from main chain", getLogAttrs(), slog.Any("error", err))
		// Continue despite error - we still want to try to clean up the chain
	}

	// Clear and delete container chain
	logger.Log(ctx, slog.LevelInfo, "Clearing and deleting container chain", getLogAttrs())
	if err := iptManager.ClearAndDeleteChain(containerChain); err != nil {
		return logAndWrap(ctx, "failed to clear and delete container chain", err)
	}

	logger.Log(ctx, slog.LevelInfo, "CNI DEL completed successfully", getLogAttrs())
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// Parse configuration
	conf, err := parseConfig(args.StdinData, args.Args, args.ContainerID)
	if err != nil {
		return err
	}

	// Create a context for this operation
	ctx := context.Background()

	logger.Log(ctx, slog.LevelInfo, "CNI CHECK called", getLogAttrs())

	// Setup iptables
	iptManager, containerChain, err := setupIPTables(ctx, conf, args.ContainerID, args.IfName)
	if err != nil {
		return err
	}

	// Check main chain
	logger.Log(ctx, slog.LevelInfo, "Checking if main chain exists", getLogAttrs())
	exists, err := iptManager.ChainExists(conf.MainChainName)
	if err != nil {
		return logAndWrap(ctx, "failed to check if main chain exists", err)
	}
	if !exists {
		logger.Log(ctx, slog.LevelError,
			"Main chain does not exist", getLogAttrs(), slog.String("chain", conf.MainChainName))
		return fmt.Errorf("main chain %s does not exist", conf.MainChainName)
	}

	// Check container chain
	logger.Log(ctx, slog.LevelInfo, "Checking container chain", getLogAttrs())
	exists, err = iptManager.ChainExists(containerChain)
	if err != nil {
		return logAndWrap(ctx, "failed to check if container chain exists", err)
	}
	if !exists {
		logger.Log(ctx, slog.LevelError,
			"Container chain does not exist", getLogAttrs(), slog.String("chain", containerChain))
		return fmt.Errorf("container chain %s does not exist", containerChain)
	}

	// Verify rules
	logger.Log(ctx, slog.LevelInfo, "Verifying rules in container chain", getLogAttrs())
	if err := iptManager.VerifyRules(containerChain, conf.OutboundRules); err != nil {
		return logAndWrap(ctx, "rule verification failed", err)
	}

	logger.Log(ctx, slog.LevelInfo, "CNI CHECK completed successfully", getLogAttrs())
	return nil
}

// main is the plugin entry point.
func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("outbound"))
}
