package projects

import (
	"log"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
)

var (
	nothing = struct{}{}
)

func SimpleWorkspaceSummariser(pm ProjectManager, workspacesToUpdate []string) (*Workspace, error) {
	wspaces, err := pm.GetWorkspaces()
	if err != nil {
		log.Printf("SimpleWorkspaceSummariser: %v", err)
		return nil, err
	}
	if len(workspacesToUpdate) > 0 {
		toUpdate := make(map[string]struct{})
		for _, w := range workspacesToUpdate {
			toUpdate[w] = nothing
		}

		ws := make(map[string][]ProjectSummary)
		for _, s := range pm.ListProjectSummaries() {
			w := s.Workspace
			if _, present := toUpdate[w]; !present {
				continue
			}
			if wsw, present := ws[w]; present {
				ws[w] = append(wsw, s)
			} else {
				ws[w] = []ProjectSummary{s}
			}
		}

		ds := make(map[string][]*diagnostics.SecurityDiagnostic)

		for w, pps := range ws {
			for _, ps := range pps {

				if sds, present := ds[w]; present {
					ds[w] = append(sds, pm.GetScanResults(ps.ID, ps.LastScanID)...)
				} else {
					ds[w] = pm.GetScanResults(ps.ID, ps.LastScanID)
				}
			}
		}

		workspaceUniqueFiles := make(map[string]map[string]struct{})

		workspaceSummary := Workspace{
			Details: make(map[string]*WorkspaceDetail),
		}
		for w, d := range ds {
			files := make(map[string]struct{})
			for _, diag := range d {
				if diag.Location != nil {
					files[*diag.Location] = nothing
				}
			}
			workspaceUniqueFiles[w] = files
			model := GenerateModel(len(files), true, d)
			model.Summarise()
			// if model, err := asciidoc.ComputeMetrics(len(files), true, d); err == nil {
			workspaceSummary.Details[w] = &WorkspaceDetail{
				Summary:          model.Summarise(),
				ProjectSummaries: ws[w],
			}
			// }
		}

		for w, wd := range workspaceSummary.Details {
			if wspaces.Details == nil {
				wspaces.Details = make(map[string]*WorkspaceDetail)
			}
			wspaces.Details[w] = wd
		}
	}
	return wspaces, nil
}
