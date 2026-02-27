//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Configuration holds the HCL configuration for the plugin.
type Configuration struct {
	// InstancesDir is the directory containing instance subdirectories,
	// each with a manifest.json file. Example: "/instances"
	InstancesDir string `hcl:"instances_dir"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("failed to decode configuration: %v", err)
		return nil
	}

	if newConfig.InstancesDir == "" {
		status.ReportError("instances_dir must be configured")
		return nil
	}

	return newConfig
}

// Manifest represents the instance manifest.json structure.
// Only fields needed for attestation are included.
type Manifest struct {
	ID            string `json:"id"`
	SandboxID     string `json:"sandboxId"`
	ObjectID      string `json:"objectId"`
	ShimProcessID int32  `json:"shimProcessId"`
	VMMProcessID  int32  `json:"vmmProcessId"`
}

// Plugin implements the SPIRE workload attestor interface.
// It scans /instances/{instanceID}/manifest.json files to match a PID
// to a shimProcessId, then returns selectors from that manifest.
type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.Mutex
	config *Configuration
	log    hclog.Logger

	// hooks for testing
	hooks struct {
		readFile func(path string) ([]byte, error)
		readDir  func(path string) ([]os.DirEntry, error)
	}
}

func New() *Plugin {
	p := &Plugin{}
	p.hooks.readFile = os.ReadFile
	p.hooks.readDir = os.ReadDir
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Attest receives a PID (the shimProcessId from delegated identity),
// scans all manifest.json files under instances_dir, and returns selectors
// for the matching instance.
func (p *Plugin) Attest(_ context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	manifest, err := p.findManifestByPID(config.InstancesDir, req.Pid)
	if err != nil {
		return nil, err
	}

	if manifest == nil {
		p.log.Warn("No manifest found for PID", "pid", req.Pid)
		return &workloadattestorv1.AttestResponse{}, nil
	}

	selectorValues := buildSelectors(manifest)

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

// findManifestByPID scans all instance directories for a manifest.json
// whose shimProcessId matches the given PID.
func (p *Plugin) findManifestByPID(instancesDir string, pid int32) (*Manifest, error) {
	entries, err := p.hooks.readDir(instancesDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read instances directory %q: %v", instancesDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		manifestPath := filepath.Join(instancesDir, entry.Name(), "manifest.json")
		data, err := p.hooks.readFile(manifestPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			p.log.Warn("Failed to read manifest", "path", manifestPath, "error", err)
			continue
		}

		var manifest Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			p.log.Warn("Failed to parse manifest", "path", manifestPath, "error", err)
			continue
		}

		if manifest.VMMProcessID == pid {
			p.log.Debug("Matched manifest to PID", "pid", pid, "instanceId", manifest.ID, "sandboxId", manifest.SandboxID)
			return &manifest, nil
		}
	}

	return nil, nil
}

// buildSelectors creates selector values from a matched manifest.
func buildSelectors(m *Manifest) []string {
	var selectors []string

	selectors = append(selectors, makeSelectorValue("sandboxId", m.SandboxID))

	if m.ID != "" {
		selectors = append(selectors, makeSelectorValue("instanceId", m.ID))
	}
	if m.ObjectID != "" {
		selectors = append(selectors, makeSelectorValue("objectId", m.ObjectID))
	}

	return selectors
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.config = newConfig
	p.mu.Unlock()

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) getConfig() (*Configuration, error) {
	p.mu.Lock()
	config := p.config
	p.mu.Unlock()
	if config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return config, nil
}

func makeSelectorValue(kind, value string) string {
	return fmt.Sprintf("%s:%s", kind, value)
}
