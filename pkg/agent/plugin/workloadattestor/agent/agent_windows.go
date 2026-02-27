//go:build windows

package agent

import (
	"context"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(_ context.Context, _ *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	return nil, status.Error(codes.Unimplemented, "the agent workload attestor is not supported on windows")
}

func (p *Plugin) Configure(_ context.Context, _ *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	return nil, status.Error(codes.Unimplemented, "the agent workload attestor is not supported on windows")
}

func (p *Plugin) Validate(_ context.Context, _ *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "the agent workload attestor is not supported on windows")
}
