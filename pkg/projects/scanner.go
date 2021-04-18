package projects

import (
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

type SecurityScanner interface {
	//runs a scan over a project, with a specific scanID, project manager provides infrastructure for interrogating
	//the project such as code repositories or locations, a prorgress callback provides indication of how the scan is progressing
	//and consumers receive the results of scan
	Scan(projectID string, scanID string, pm ProjectManager,
		callback func(diagnostics.Progress), consumers ...diagnostics.SecurityDiagnosticsConsumer)
}
