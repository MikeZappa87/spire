//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeManifest creates an instance directory with a manifest.json file.
func writeManifest(t *testing.T, instancesDir, instanceID string, manifest map[string]any) {
	t.Helper()
	dir := filepath.Join(instancesDir, instanceID)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644))
}

func TestAttest_MatchesShimPID(t *testing.T) {
	instancesDir := t.TempDir()

	writeManifest(t, instancesDir, "instance-aaa", map[string]any{
		"id":            "instance-aaa",
		"sandboxId":     "sandbox-111",
		"objectId":      "obj-aaa",
		"shimProcessId": 99999,
		"vmmProcessId":  99998,
		"lifecycle":     "running",
		"privilegeMode": "standard",
		"egressPolicy":  "block",
	})

	writeManifest(t, instancesDir, "instance-bbb", map[string]any{
		"id":            "instance-bbb",
		"sandboxId":     "sandbox-222",
		"objectId":      "obj-bbb",
		"shimProcessId": 12345,
		"vmmProcessId":  12347,
		"lifecycle":     "running",
		"privilegeMode": "standard",
		"egressPolicy":  "allow",
	})

	p := New()
	p.log = hclog.NewNullLogger()
	p.config = &Configuration{InstancesDir: instancesDir}

	resp, err := p.Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: 12345})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Contains(t, resp.SelectorValues, "sandboxId:sandbox-222")
	assert.Contains(t, resp.SelectorValues, "instanceId:instance-bbb")
	assert.Contains(t, resp.SelectorValues, "objectId:obj-bbb")
	assert.Contains(t, resp.SelectorValues, "lifecycle:running")
	assert.Contains(t, resp.SelectorValues, "privilegeMode:standard")
	assert.Contains(t, resp.SelectorValues, "egressPolicy:allow")
}

func TestAttest_NoMatchingPID(t *testing.T) {
	instancesDir := t.TempDir()

	writeManifest(t, instancesDir, "instance-aaa", map[string]any{
		"id":            "instance-aaa",
		"sandboxId":     "sandbox-111",
		"shimProcessId": 99999,
	})

	p := New()
	p.log = hclog.NewNullLogger()
	p.config = &Configuration{InstancesDir: instancesDir}

	resp, err := p.Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: 11111})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.SelectorValues)
}

func TestAttest_EmptyInstancesDir(t *testing.T) {
	instancesDir := t.TempDir()

	p := New()
	p.log = hclog.NewNullLogger()
	p.config = &Configuration{InstancesDir: instancesDir}

	resp, err := p.Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: 1})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.SelectorValues)
}

func TestAttest_SkipsMalformedManifest(t *testing.T) {
	instancesDir := t.TempDir()

	// Write a malformed manifest
	dir := filepath.Join(instancesDir, "bad-instance")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("not json"), 0o644))

	// Write a valid manifest
	writeManifest(t, instancesDir, "good-instance", map[string]any{
		"id":            "good-instance",
		"sandboxId":     "sandbox-good",
		"shimProcessId": 42,
	})

	p := New()
	p.log = hclog.NewNullLogger()
	p.config = &Configuration{InstancesDir: instancesDir}

	resp, err := p.Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: 42})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Contains(t, resp.SelectorValues, "sandboxId:sandbox-good")
}

func TestAttest_SkipsDirWithNoManifest(t *testing.T) {
	instancesDir := t.TempDir()

	// Directory with no manifest.json
	require.NoError(t, os.MkdirAll(filepath.Join(instancesDir, "empty-instance"), 0o755))

	// Valid manifest
	writeManifest(t, instancesDir, "real-instance", map[string]any{
		"id":            "real-instance",
		"sandboxId":     "sandbox-real",
		"shimProcessId": 7,
	})

	p := New()
	p.log = hclog.NewNullLogger()
	p.config = &Configuration{InstancesDir: instancesDir}

	resp, err := p.Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: 7})
	require.NoError(t, err)
	assert.Contains(t, resp.SelectorValues, "sandboxId:sandbox-real")
}

func TestAttest_NotConfigured(t *testing.T) {
	p := New()
	p.log = hclog.NewNullLogger()

	_, err := p.Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

func TestAttest_MultipleInstances(t *testing.T) {
	instancesDir := t.TempDir()

	// Create 5 instances, only one matches
	for i := 0; i < 5; i++ {
		writeManifest(t, instancesDir, fmt.Sprintf("instance-%d", i), map[string]any{
			"id":            fmt.Sprintf("instance-%d", i),
			"sandboxId":     fmt.Sprintf("sandbox-%d", i),
			"shimProcessId": 1000 + i,
		})
	}

	p := New()
	p.log = hclog.NewNullLogger()
	p.config = &Configuration{InstancesDir: instancesDir}

	resp, err := p.Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: 1003})
	require.NoError(t, err)
	assert.Contains(t, resp.SelectorValues, "sandboxId:sandbox-3")
	assert.Contains(t, resp.SelectorValues, "instanceId:instance-3")
}
