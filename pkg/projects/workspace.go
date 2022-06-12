package projects

import (
	"log"
	"time"
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

		ws := make(map[string][]*ProjectSummary)
		for _, s := range pm.ListProjectSummaries() {
			w := s.Workspace
			if _, present := toUpdate[w]; !present {
				continue
			}
			if wsw, present := ws[w]; present {
				ws[w] = append(wsw, s)
			} else {
				ws[w] = []*ProjectSummary{s}
			}
		}

		// ds := make(map[string][]*diagnostics.SecurityDiagnostic)

		// for w, pps := range ws {
		// 	for _, ps := range pps {
		// 		if results, err := pm.GetScanResults(ps.ID, ps.LastScanID); err == nil {
		// 			if sds, present := ds[w]; present {
		// 				ds[w] = append(sds, results...)
		// 			} else {
		// 				ds[w] = results
		// 			}
		// 		}
		// 	}
		// }

		// workspaceUniqueFiles := make(map[string]map[string]struct{})

		// for w, d := range ds {
		// 	files := make(map[string]struct{})
		// 	for _, diag := range d {
		// 		if diag.Location != nil {
		// 			files[*diag.Location] = nothing
		// 		}
		// 	}
		// 	workspaceUniqueFiles[w] = files
		// 	model := GenerateModel(len(files), true, d)
		// 	scanSummary := model.Summarise()
		// 	workspaceSummary.Details[w] = &WorkspaceDetail{
		// 		Summary:          scanSummary,
		// 		ProjectSummaries: ws[w],
		// 	}
		// }

		workspaceSummary := Workspace{
			Details: make(map[string]*WorkspaceDetail),
		}

		tStamp := time.Now().UTC().Format(time.RFC1123)
		for w, pss := range ws {
			psModels := make([]*Model, len(pss))
			for _, ps := range pss {
				psModels = append(psModels, ps.LastScanSummary.AdditionalInfo)
			}
			workspaceSummary.Details[w] = &WorkspaceDetail{
				Summary:          MergeModels(tStamp, psModels...).Summarise(),
				ProjectSummaries: ws[w],
			}
		}

		if wspaces.Details == nil {
			wspaces.Details = make(map[string]*WorkspaceDetail)
		}

		//update the newly-calculated workspace summary details
		for w, wd := range workspaceSummary.Details {
			wspaces.Details[w] = wd
		}
	}
	return wspaces, nil
}
