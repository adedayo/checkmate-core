package plugins

import (
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
)

type DiagnosticTransformer interface {
	Transform(...*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic
	Init(*PluginInitialiser) error
}

type PluginInitialiser struct {
	ProjectManager projects.ProjectManager
	ProjectID      string
}
