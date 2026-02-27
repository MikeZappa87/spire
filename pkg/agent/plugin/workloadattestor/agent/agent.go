package agent

import "github.com/spiffe/spire/pkg/common/catalog"

const (
	pluginName = "agent"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}
