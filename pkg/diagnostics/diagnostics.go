package diagnostics

import (
	"encoding/json"
	"fmt"

	"github.com/adedayo/checkmate-core/pkg/code"
)

//SecurityDiagnostic describes a security issue
type SecurityDiagnostic struct {
	Justification  Justification
	Range          code.Range
	HighlightRange code.Range
	//Source code evidence optionally provided
	Source *string `json:"source,omitempty"`
	//SHA256 checksum is an optional SHA256 hash of the secret. High-security environments
	//may want to consider using an HMAC or similar and ommitting source from the reports
	SHA256 *string `json:"sha256,omitempty"`
	//Location is an optional value that could contain filepath or URI of resource that this diagnostic applies to
	Location *string `json:"location,omitempty"`
	//used for identifying the source of the diagnostics
	ProviderID *string `json:"providerID,omitempty"`
	Excluded   bool    //indicates whether or not this diagnostics has been excluded
}

//GoString stringify
func (sd SecurityDiagnostic) GoString() string {
	sd.Range = adjustRange(sd.Range)
	sd.HighlightRange = adjustRange(sd.HighlightRange)
	b, _ := json.Marshal(sd)
	return string(b)
}

//adjust the 0-based position to 1-based for easy human debugging
func adjustRange(in code.Range) (out code.Range) {
	out.Start.Line = in.Start.Line + 1
	out.Start.Character = in.Start.Character + 1
	out.End.Line = in.End.Line + 1
	out.End.Character = in.End.Character + 1
	return
}

//Confidence reflects the degree of confidence that we have in an assessment
type Confidence int

const (
	//Low Confidence in the assessment
	Low Confidence = iota
	//Medium Confidence in the assessment
	Medium
	//High Confidence in the assessment
	High
)

func (conf Confidence) String() string {
	switch conf {
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	default:
		return "Unknown"
	}
}

//GoString go stringify
func (conf Confidence) GoString() string {
	return conf.String()
}

//MarshalJSON makes a string representation of the confidence
func (conf Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(conf.String())
}

//UnmarshalJSON makes a string representation of the confidence
func (conf *Confidence) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, conf); err != nil {
		var c string
		if err := json.Unmarshal(data, &c); err != nil {
			return err
		}
		switch c {
		case Low.String():
			*conf = Low
		case Medium.String():
			*conf = Medium
		case High.String():
			*conf = High
		default:
			return fmt.Errorf(`Unknown Confidence type: "%s"`, c)
		}
	}
	return nil
}

//Evidence is an atomic piece of information that describes a security diagnostics
type Evidence struct {
	Description string
	Confidence  Confidence
}

//Justification describes why a piece of security diagnostic has been generated
type Justification struct {
	Headline Evidence   //Headline evidence
	Reasons  []Evidence //sub-reasons that justify why this is an issue
}

//SecurityDiagnosticsProvider interface for security diagnostics providers
type SecurityDiagnosticsProvider interface {
	//AddConsumers adds consumers to be notified by this provider when there is a new diagnostics
	AddConsumers(consumers ...SecurityDiagnosticsConsumer)
	Broadcast(diagnostic SecurityDiagnostic)
}

//SecurityDiagnosticsConsumer is an interface with a callback to receive security diagnostics
type SecurityDiagnosticsConsumer interface {
	ReceiveDiagnostic(diagnostic SecurityDiagnostic)
}

//DefaultSecurityDiagnosticsProvider a default implementation
type DefaultSecurityDiagnosticsProvider struct {
	consumers []SecurityDiagnosticsConsumer
}

//AddConsumers adds consumers to be notified by this provider when there is a new diagnostics
func (sdp *DefaultSecurityDiagnosticsProvider) AddConsumers(consumers ...SecurityDiagnosticsConsumer) {
	sdp.consumers = append(sdp.consumers, consumers...)
}

//Broadcast sends diagnostics to all registered consumers
func (sdp *DefaultSecurityDiagnosticsProvider) Broadcast(diagnostics SecurityDiagnostic) {
	for _, c := range sdp.consumers {
		c.ReceiveDiagnostic(diagnostics)
	}
}
