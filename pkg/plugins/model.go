package plugins

import (
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

type DiagnosticTransformer interface {
	Transform(*Config, ...*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic
}

type Config struct {
	CodeBaseDir string // code base directory
	ProjectID   string
}

type ConfigDiagnostics struct {
	Config      *Config
	Diagnostics []*diagnostics.SecurityDiagnostic
}
