package plugins

import (
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

type DiagnosticTransformer interface {
	Transform(*Config, ...*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic
}

type Config struct {
	// ProjectManager projects.ProjectManager
	CodeBaseDir string // code base directory
	ProjectID   string
}

type ConfigDiagnostics struct {
	Config      *Config
	Diagnostics []*diagnostics.SecurityDiagnostic
}

// type TransformerPlugin struct {
// 	Impl DiagnosticTransformer
// }

// func (t *TransformerPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
// 	return &TransformerRPCServer{Impl: t.Impl}, nil
// }

// func (TransformerPlugin) Client(_ *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
// 	return &TransformerRPC{client: c}, nil
// }

// type TransformerRPCServer struct {
// 	Impl DiagnosticTransformer
// }

// func (s *TransformerRPCServer) Transform(diag []*diagnostics.SecurityDiagnostic, out []*diagnostics.SecurityDiagnostic) error {
// 	out = s.Impl.Transform(diag...)
// 	return nil
// }

// func (s *TransformerRPCServer) Init(config *PluginInitialiser) error {
// 	return s.Impl.Init(config)
// }

// type TransformerRPC struct {
// 	client *rpc.Client
// }

// func (t *TransformerRPC) Init(config *PluginInitialiser) error {

// 	err := t.client.Call("Plugin.Init", config, nil)

// 	if err != nil {
// 		log.Printf("Error invoking plugin Init: %v", err)
// 	}

// 	return err
// }

// func (t *TransformerRPC) Transform(diags ...*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic {
// 	var out []*diagnostics.SecurityDiagnostic
// 	err := t.client.Call("Plugin.Transform", diags, &out)
// 	if err != nil {
// 		log.Printf("Error invoking plugin Transform: %v", err)
// 	}
// 	return out
// }
