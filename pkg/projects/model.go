package projects

import (
	"encoding/json"
	"log"
	"time"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/scores"
)

type Project struct {
	ID           string       `yaml:"ID"`   //unique
	Name         string       `yaml:"Name"` //human-friendly
	Repositories []Repository `yaml:"Repositories,omitempty"`
	ScanIDs      []string     `yaml:"ScanIDs"`
	ScanPolicy   ScanPolicy   `yaml:"ScanPolicy"`
}

//ProjectDescription used to create new/update projects
type ProjectDescription struct {
	Name         string       `yaml:"Name"` //human-friendly
	Repositories []Repository `yaml:"Repositories,omitempty"`
	ScanPolicy   ScanPolicy   `yaml:"ScanPolicy"`
}

//ProjectDescriptionWire used to create new/update projects (wire representation)
type ProjectDescriptionWire struct {
	Name         string         `yaml:"Name"` //human-friendly
	Repositories []Repository   `yaml:"Repositories,omitempty"`
	ScanPolicy   ScanPolicyWire `yaml:"ScanPolicy"`
}

func (desc ProjectDescriptionWire) ToProjectDescription() ProjectDescription {
	var policy diagnostics.ExcludeDefinition
	if err := json.Unmarshal([]byte(desc.ScanPolicy.Policy), &policy); err != nil {
		log.Printf("Error parsing scan exclusion, reverting to default: %s", err.Error())
		policy = diagnostics.ExcludeDefinition{}
	}
	return ProjectDescription{
		Name:         desc.Name,
		Repositories: desc.Repositories,
		ScanPolicy: ScanPolicy{
			ID:     desc.ScanPolicy.ID,
			Config: desc.ScanPolicy.Config,
			Policy: policy,
		},
	}
}

type Repository struct {
	Location     string `yaml:"Location"`
	LocationType string `yaml:"LocationType"` //filesystem, git, svn etc.
}

type Scan struct {
	ID         string
	Score      scores.Score
	Start, End time.Time
	Issues     []diagnostics.SecurityDiagnostic
	Policy     ScanPolicy
}

type ScanPolicyWire struct {
	ID     string                 `yaml:"ID"`
	Policy string                 `yaml:"Policy,omitempty"`
	Config map[string]interface{} //indexes to scan configurations, key secrets for secret finder
}
type ScanPolicy struct {
	ID     string                        `yaml:"ID"`
	Policy diagnostics.ExcludeDefinition `yaml:"Policy,omitempty"`
	Config map[string]interface{}        //indexes to scan configurations, key secrets for secret finder
}

type ProjectSummary struct {
	ID               string       `yaml:"ID"`
	Name             string       `yaml:"Name"`
	Repositories     []Repository `yaml:"Repositories,omitempty"`
	LastScanID       string       `yaml:"LastScanID"`
	LastScore        scores.Score `yaml:"LastScore"`
	IsBeingScanned   bool         `yaml:"IsBeingScanned"`
	CreationDate     time.Time    `yaml:"CreationDate"`
	LastModification time.Time    `yaml:"LastModification"`
	LastScan         time.Time    `yaml:"LastScan"`
}

type ScanSummary struct {
	Score          scores.Score
	AdditionalInfo interface{}
}
