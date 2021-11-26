package projects

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/scores"
	"gopkg.in/yaml.v3"
)

type Workspace struct {
	Details map[string]*WorkspaceDetail `json:"Details" yaml:"Details"`
}

type WorkspaceDetail struct {
	Summary          *ScanSummary     `json:"Summary" yaml:"Summary"`
	ProjectSummaries []ProjectSummary `json:"ProjectSummaries" yaml:"ProjectSummaries"`
}

type Project struct {
	ID                   string       `yaml:"ID"`                   //unique
	Name                 string       `yaml:"Name"`                 //human-friendly
	Workspace            string       `yaml:"Workspace"`            //Used to group related projects
	DeleteCheckedOutCode bool         `yaml:"DeleteCheckedOutCode"` //whether to delete code checked out after scan is complete
	Repositories         []Repository `yaml:"Repositories,omitempty"`
	ScanIDs              []string     `yaml:"ScanIDs"`
	ScanPolicy           ScanPolicy   `yaml:"ScanPolicy"`
}

//ProjectDescription used to create new/update projects
type ProjectDescription struct {
	Name         string       `yaml:"Name"` //human-friendly
	Repositories []Repository `yaml:"Repositories,omitempty"`
	Workspace    string       `yaml:"Workspace"` //Used to group related projects
	ScanPolicy   ScanPolicy   `yaml:"ScanPolicy"`
}

//ProjectDescriptionWire used to create new/update projects (wire representation)
type ProjectDescriptionWire struct {
	Name         string         `yaml:"Name"` //human-friendly
	Repositories []Repository   `yaml:"Repositories,omitempty"`
	Workspace    string         `yaml:"Workspace"` //Used to group related projects
	ScanPolicy   ScanPolicyWire `yaml:"ScanPolicy"`
}

func (desc ProjectDescriptionWire) ToProjectDescription() (ProjectDescription, error) {

	var policy diagnostics.ExcludeDefinition
	pDesc := ProjectDescription{
		Name:         desc.Name,
		Repositories: desc.Repositories,
		Workspace:    desc.Workspace,
		ScanPolicy: ScanPolicy{
			ID:     desc.ScanPolicy.ID,
			Config: desc.ScanPolicy.Config,
			Policy: diagnostics.ExcludeDefinition{},
		}}

	if desc.ScanPolicy.PolicyString == "" {
		return pDesc, nil
	}

	if err := yaml.Unmarshal([]byte(desc.ScanPolicy.PolicyString), &policy); err != nil {
		log.Printf("Error parsing scan exclusion, reverting to default: %s", err.Error())
		return ProjectDescription{
			Name:         desc.Name,
			Repositories: desc.Repositories,
			Workspace:    desc.Workspace,
			ScanPolicy: ScanPolicy{
				ID:           desc.ScanPolicy.ID,
				Config:       desc.ScanPolicy.Config,
				Policy:       diagnostics.ExcludeDefinition{},
				PolicyString: desc.ScanPolicy.PolicyString,
			}}, fmt.Errorf("error parsing scan exclusion, reverting to default: %s", err.Error())
	}
	pDesc.ScanPolicy.Policy = policy
	return pDesc, nil
}

type Repository struct {
	Location     string `yaml:"Location"`
	LocationType string `yaml:"LocationType"` //filesystem, git, svn etc.
	GitServiceID string `yaml:"GitServiceID"` /*if this repository is from a "private" on-prem instance,
	the service ID is used to locate the instance and associated API keys etc*/
}

type Scan struct {
	ID         string
	Score      scores.Score
	Start, End time.Time
	Issues     []diagnostics.SecurityDiagnostic
	Policy     ScanPolicy
}

type ScanPolicyWire struct {
	ID           string `yaml:"ID"`
	Policy       string `yaml:"Policy,omitempty"`
	PolicyString string
	Config       map[string]interface{} //indexes to scan configurations, key secrets for secret finder
}
type ScanPolicy struct {
	ID           string                        `yaml:"ID"`
	Policy       diagnostics.ExcludeDefinition `yaml:"Policy,omitempty"`
	PolicyString string                        `yaml:"-"`
	Config       map[string]interface{}        //indexes to scan configurations, use the key "secrets" for secret finder
}

func (sp ScanPolicy) MarshalJSON() ([]byte, error) {
	type Alias ScanPolicy
	policy, err := yaml.Marshal(sp.Policy)
	if err != nil {
		return []byte(err.Error()), err
	}
	pol := ""
	if len(policy) == 0 {
		pol = diagnostics.GenerateSampleExclusion()
	} else {
		pol = string(policy)
	}
	return json.Marshal(&struct {
		*Alias
		PolicyString string
	}{
		Alias:        (*Alias)(&sp),
		PolicyString: pol,
	})
}

type ProjectSummary struct {
	ID               string       `yaml:"ID"`
	Name             string       `yaml:"Name"`
	Workspace        string       `yaml:"Workspace"` //Used to group related projects
	Repositories     []Repository `yaml:"Repositories,omitempty"`
	LastScanID       string       `yaml:"LastScanID"`
	LastScanSummary  ScanSummary  `yaml:"LastScanSummary"`
	LastScore        scores.Score `yaml:"LastScore"`
	IsBeingScanned   bool         `yaml:"IsBeingScanned"`
	CreationDate     time.Time    `yaml:"CreationDate"`
	LastModification time.Time    `yaml:"LastModification"`
	LastScan         time.Time    `yaml:"LastScan"`
}

func (ps ProjectSummary) CSVHeaders() []string {
	return []string{
		`Project Name`,
		`Grade (A-F)`,
		`Metric (Score out of 100)`,
		`Critical Issues Count`,
		`High Issues Count`,
		`Medium Issues Count`,
		`Low Issues Count`,
		`Informational Issues Count`,
		`Workspace`,
		`Repositories`,
		`ID`,
	}
}

func (ps *ProjectSummary) CSVValues() []string {
	reps := []string{}
	for _, r := range ps.Repositories {
		reps = append(reps, r.Location)
	}
	return []string{
		ps.Name,
		ps.LastScanSummary.Score.Grade,
		roundDown(ps.LastScanSummary.Score.Metric),
		getSeverity(ps, `criticalCount`),
		getSeverity(ps, `highCount`),
		getSeverity(ps, `mediumCount`),
		getSeverity(ps, `lowCount`),
		getSeverity(ps, `informationalCount`),
		ps.Workspace,
		strings.Join(reps, "; "),
		ps.ID,
	}

}

func getSeverity(ps *ProjectSummary, criticality string) string {
	if info, ok := ps.LastScanSummary.AdditionalInfo.(map[string]interface{}); ok {
		if val, ok2 := info[criticality].(int); ok2 {
			return fmt.Sprintf("%d", val)
		}
	}
	return ""

}

func roundDown(num float32) string {
	return fmt.Sprintf("%d", int64(num))
}

func (ps *ProjectSummary) MarshalJSON() ([]byte, error) {
	type Alias ProjectSummary
	return json.Marshal(&struct {
		*Alias
		CreationDate     string
		LastModification string
		LastScan         string
	}{
		Alias:            (*Alias)(ps),
		CreationDate:     ps.CreationDate.Format(time.RFC3339),
		LastModification: ps.LastModification.Format(time.RFC3339),
		LastScan:         ps.LastScan.Format(time.RFC3339),
	})
}

type ScanSummary struct {
	Score          scores.Score
	AdditionalInfo interface{}
}

type PaginatedIssueSearch struct {
	ProjectID string
	ScanID    string
	PageSize  int
	Page      int
	Filter    IssueFilter
}

type IssueFilter struct {
	Confidence []string //high, med, low, info
	Tags       []string //test, prod
}
type PagedResult struct {
	Total       int
	Page        int
	Diagnostics []*diagnostics.SecurityDiagnostic
}
