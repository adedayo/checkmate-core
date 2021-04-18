package projects

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/util"
	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v3"
)

var (
	defaultProjectFile     = "project.yaml"
	projectSummaryFile     = "project-summary.yaml"
	defaultScanFile        = "scanConfig.yaml"
	defaultScanResultsFile = "scanResults.json"
	defaultScanSummaryFile = "scan-summary.yaml"
)

type ProjectManager interface {
	ListProjectSummaries() []ProjectSummary
	GetProjectSummary(projectID string) ProjectSummary
	GetProject(id string) Project //if project does not exist, we get an "empty" struct. Check the ID=id in client
	GetScanConfig(projectID, scanID string) ScanPolicy
	GetScanResults(projectID, scanID string) []*diagnostics.SecurityDiagnostic
	GetScanResultSummary(projectID, scanID string) interface{}
	// SummariseScanResults(projectID, scanID string, summariser func(projectID, scanID string, issues []*diagnostics.SecurityDiagnostic) *ScanSummary) error
	RunScan(projectID string, scanPolicy ScanPolicy, scanner SecurityScanner,
		scanIDCallback func(string), progressMonitor func(diagnostics.Progress),
		summariser func(projectID, scanID string, issues []*diagnostics.SecurityDiagnostic) *ScanSummary,
		consumers ...diagnostics.SecurityDiagnosticsConsumer)

	CreateProject(projectDescription ProjectDescription) Project
	UpdateProject(projectID string, projectDescription ProjectDescription) Project
}

func MakeSimpleProjectManager() ProjectManager {
	location := "."
	if loc, err := homedir.Expand("~/.checkmate/projects"); err == nil {
		location = loc
	}

	pm := simpleProjectManager{
		projectsLocation: location,
	}
	return pm
}

type simpleProjectManager struct {
	projectsLocation string
}

func (spm simpleProjectManager) CreateProject(projectDescription ProjectDescription) (project Project) {
	projectID := util.NewRandomUUID().String()
	policy := ScanPolicy{
		ID:     util.NewRandomUUID().String(),
		Policy: projectDescription.ScanPolicy.Policy,
	}

	proj := Project{
		ID:           projectID,
		Name:         projectDescription.Name,
		Repositories: projectDescription.Repositories,
		ScanPolicy:   policy,
	}

	return spm.saveProject(proj, projectStatus{created: true, creationTime: time.Now()})
}

func (spm simpleProjectManager) GetProject(id string) (project Project) {
	if dirs, err := os.ReadDir(spm.projectsLocation); err == nil {
		for _, dir := range dirs {
			if dir.IsDir() && dir.Name() == id {
				return loadProject(path.Join(spm.projectsLocation, dir.Name()))
			}
		}
	}
	return
}

func (spm simpleProjectManager) GetScanResults(projID, scanID string) (results []*diagnostics.SecurityDiagnostic) {
	scanResultsLocation := path.Join(spm.projectsLocation, projID, scanID, defaultScanResultsFile)
	file, err := os.Open(scanResultsLocation)
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	for {
		if err := decoder.Decode(&results); err == io.EOF {
			break
		} else if err != nil {
			return
		}
	}
	return
}

func (spm simpleProjectManager) summariseScanResults(projectID, scanID string, summariser func(projectID, scanID string, issues []*diagnostics.SecurityDiagnostic) *ScanSummary) (*ScanSummary, error) {
	results := spm.GetScanResults(projectID, scanID)
	out := summariser(projectID, scanID, results)
	scanSummaryFile, err := os.Create(path.Join(spm.projectsLocation, projectID, scanID, defaultScanSummaryFile))
	if err != nil {
		return out, err
	}
	defer scanSummaryFile.Close()
	return out, yaml.NewEncoder(scanSummaryFile).Encode(out)
}

func (spm simpleProjectManager) GetScanResultSummary(projectID, scanID string) (out interface{}) {
	scanSummaryFile, err := os.Open(path.Join(spm.projectsLocation, projectID, scanID, defaultScanSummaryFile))
	if err != nil {
		return
	}
	defer scanSummaryFile.Close()
	yaml.NewDecoder(scanSummaryFile).Decode(out)
	return
}

func (spm simpleProjectManager) GetScanConfig(projID, scanID string) (config ScanPolicy) {
	data, err := os.ReadFile(path.Join(spm.projectsLocation, projID, scanID, defaultScanFile))
	if err == nil {
		if yaml.Unmarshal(data, &config) != nil {
			return ScanPolicy{}
		}
	}
	return
}

func loadProject(projPath string) (proj Project) {
	data, err := os.ReadFile(path.Join(projPath, defaultProjectFile))
	if err == nil {
		if yaml.Unmarshal(data, &proj) != nil {
			return Project{}
		}
	}
	return
}

func (spm simpleProjectManager) GetProjectSummary(projID string) (summary ProjectSummary) {
	projPath := path.Join(spm.projectsLocation, projID)
	data, err := os.ReadFile(path.Join(projPath, projectSummaryFile))
	if err == nil {
		if yaml.Unmarshal(data, &summary) != nil {
			return ProjectSummary{}
		}
	}
	return
}

func (spm simpleProjectManager) loadLastScanSummary(projID, scanID string) (summary ScanSummary) {
	if file, err := os.Open(path.Join(spm.projectsLocation, projID, scanID, defaultScanSummaryFile)); err == nil {
		yaml.NewDecoder(file).Decode(&summary)
	} else {
		log.Printf("Error loading scan summary: %s", err.Error())
	}
	return
}

func (spm simpleProjectManager) ListProjectSummaries() (summaries []ProjectSummary) {

	if files, err := ioutil.ReadDir(spm.projectsLocation); err == nil {
		for _, file := range files {
			if file.IsDir() {
				summary := spm.GetProjectSummary(file.Name())
				if summary.ID != "" {
					summaries = append(summaries, summary)
				}
			}
		}
	}
	return
}

func (spm simpleProjectManager) RunScan(projectID string, scanPolicy ScanPolicy, scanner SecurityScanner,
	scanIDCallback func(string), progressMonitor func(diagnostics.Progress),
	summariser func(projectID, scanID string, issues []*diagnostics.SecurityDiagnostic) *ScanSummary,
	consumers ...diagnostics.SecurityDiagnosticsConsumer) {
	scanID := spm.createScan(projectID, scanPolicy)
	scanIDCallback(scanID)
	sdc := createDiagnosticConsumer(spm.projectsLocation, projectID, scanID)
	consumers = append(consumers, sdc)
	scanStartTime := time.Now()
	scanner.Scan(projectID, scanID, spm, progressMonitor, consumers...)
	scanEndTime := time.Now()
	sdc.close(scanStartTime, scanEndTime)
	if out, err := spm.summariseScanResults(projectID, scanID, summariser); err == nil {
		project := spm.GetProject(projectID)
		spm.saveProject(project, projectStatus{scanned: true, scanID: scanID, scanTime: out.Score.TimeStamp})
	}

}

func (spm simpleProjectManager) UpdateProject(projectID string, projectDescription ProjectDescription) (project Project) {
	proj := spm.GetProject(projectID)
	if proj.ID == projectID {
		//found project, update
		proj.Name = projectDescription.Name
		proj.Repositories = projectDescription.Repositories
		policy := ScanPolicy{
			ID:     util.NewRandomUUID().String(),
			Policy: projectDescription.ScanPolicy.Policy,
		}
		proj.ScanPolicy = policy
		return spm.saveProject(proj, projectStatus{modified: true, modifiedTime: time.Now()})
	}
	//project not found, create one with a new ID
	return spm.CreateProject(projectDescription)

}

func (spm simpleProjectManager) saveProjectSummary(summary ProjectSummary) error {
	projectLoc := path.Join(spm.projectsLocation, summary.ID)
	projSummaryFile, err := os.Create(path.Join(projectLoc, projectSummaryFile))
	if err != nil {
		return err
	}
	defer projSummaryFile.Close()

	summaryData, err := yaml.Marshal(summary)
	if err != nil {
		return err
	}
	if _, err = projSummaryFile.Write(summaryData); err != nil {
		return err
	}
	return nil
}

func (spm simpleProjectManager) saveProject(project Project, status projectStatus) (_ Project) {

	projectLoc := path.Join(spm.projectsLocation, project.ID)
	if err := os.MkdirAll(projectLoc, 0755); err != nil {
		return
	}

	data, err := yaml.Marshal(project)
	if err != nil {
		return
	}

	projFile, err := os.Create(path.Join(projectLoc, defaultProjectFile))
	if err != nil {
		return
	}
	defer projFile.Close()
	if _, err = projFile.Write(data); err != nil {
		return
	}

	if status.created {

		summary := ProjectSummary{
			ID:           project.ID,
			Name:         project.Name,
			CreationDate: status.creationTime,
			Repositories: project.Repositories,
		}

		spm.saveProjectSummary(summary)
	}

	if status.scanned || status.modified || status.newScan {
		summary := spm.GetProjectSummary(project.ID)
		if summary.ID == project.ID {

			if status.scanned {
				summary.LastScanID = status.scanID
				summary.LastScan = status.scanTime
				scanSummary := spm.loadLastScanSummary(project.ID, status.scanID)
				if scanSummary.Score.TimeStamp.Equal(status.scanTime) { //use this to gate errors in (de)serialisation
					summary.LastScore = scanSummary.Score
				} else {
					log.Printf("unable to load last score, %s, %s\n", scanSummary.Score.TimeStamp, status.scanTime)
				}
			}

			if status.modified {
				summary.LastModification = status.modifiedTime
				summary.Repositories = project.Repositories
			}

			if status.newScan {
				summary.LastScanID = status.scanID
				summary.LastModification = status.modifiedTime
			}
			spm.saveProjectSummary(summary)
		}
	}

	return project
}

func (spm simpleProjectManager) createScan(projectID string, scanPolicy ScanPolicy) (scanID string) {

	proj := spm.GetProject(projectID)
	if projectID != proj.ID {
		//project does not exist
		return
	}

	scanID = util.NewRandomUUID().String()
	proj.ScanIDs = append(proj.ScanIDs, scanID)
	spm.saveProject(proj, projectStatus{newScan: true, scanID: scanID, modifiedTime: time.Now()})

	policy := ScanPolicy{
		ID:     scanID,
		Policy: scanPolicy.Policy,
	}

	if err := spm.saveScan(projectID, scanID, policy); err != nil {
		return ""
	}

	return
}

func (spm simpleProjectManager) saveScan(projID, scanID string, policy ScanPolicy) error {

	scanLoc := path.Join(spm.projectsLocation, projID, scanID)
	if err := os.MkdirAll(scanLoc, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(policy)
	if err != nil {
		return err
	}

	scanConfigFile, err := os.Create(path.Join(scanLoc, defaultScanFile))
	if err != nil {
		return err
	}
	defer scanConfigFile.Close()

	if _, err = scanConfigFile.Write(data); err != nil {
		return err
	}

	return nil
}

type simpleDiagnosticConsumer struct {
	scanLocation string
	diagnostics  []*diagnostics.SecurityDiagnostic
}

func (sdc *simpleDiagnosticConsumer) ReceiveDiagnostic(diag *diagnostics.SecurityDiagnostic) {
	sdc.diagnostics = append(sdc.diagnostics, diag)
}

func (sdc *simpleDiagnosticConsumer) close(start, end time.Time) error {
	//write the collected diagnostics to file
	filePath := path.Join(sdc.scanLocation, defaultScanResultsFile)
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(sdc.diagnostics); err != nil {
		return err
	}
	return nil
}

func createDiagnosticConsumer(projectLocation, projectID, scanID string) *simpleDiagnosticConsumer {
	sdc := simpleDiagnosticConsumer{
		scanLocation: path.Join(projectLocation, projectID, scanID),
		diagnostics:  []*diagnostics.SecurityDiagnostic{},
	}

	return &sdc
}

type projectStatus struct {
	created, scanned, modified bool
	newScan/**create scan without actually running it*/ bool
	creationTime, scanTime, modifiedTime time.Time
	scanID                               string
}
