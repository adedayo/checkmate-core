package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/adedayo/checkmate-core/pkg/code"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

//SecurityDiagnostic describes a security issue
type SecurityDiagnostic struct {
	Justification  Justification `json:"justification,omitempty"`
	Range          code.Range    `json:"range,omitempty"`
	RawRange       CharRange     `json:"rawRange,omitempty"`
	HighlightRange code.Range    `json:"highlightRange,omitempty"`
	//Source code evidence optionally provided
	Source *string `json:"source,omitempty"`
	//SHA256 checksum is an optional SHA256 hash of the secret. High-security environments
	//may want to consider using an HMAC or similar and ommitting source from the reports
	SHA256 *string `json:"sha256,omitempty"`
	//Location is an optional value that could contain filepath or URI of resource that this diagnostic applies to
	Location *string `json:"location,omitempty"`
	//used for identifying the source of the diagnostics
	ProviderID *string   `json:"providerID,omitempty"`
	Excluded   bool      //indicates whether or not this diagnostics has been excluded
	Tags       *[]string `json:"tags,omitempty"` //optionally annotate diagnostic with tags, e.g. "test"
}

func (sd *SecurityDiagnostic) CSVHeaders() []string {
	return []string{
		`Code`, //Source
		`File`, //Location
		`Description`,
		`Severity`,
		`File Location`, //Range Start Position
		`SHA256`,
		`Tags`,
		`Detector ID`, // ProviderID
	}
}

func nilAsEmpty(x *string) string {
	if x == nil {
		return ""
	}
	return *x
}

func nilArrayAsEmpty(x *[]string) string {
	if x == nil {
		return ""
	}
	return strings.Join(*x, " ")
}

func (sd *SecurityDiagnostic) CSVValues() []string {
	rng := adjustRange(sd.Range)
	loc := fmt.Sprintf(`Line: %d Column: %d`, rng.Start.Line, rng.Start.Character)
	return []string{
		nilAsEmpty(sd.Source),
		nilAsEmpty(sd.Location),
		sd.Justification.Headline.Description,
		sd.Justification.Headline.Confidence.String(),
		loc,
		nilAsEmpty(sd.SHA256),
		nilArrayAsEmpty(sd.Tags),
		nilAsEmpty(sd.ProviderID),
	}
}

//HasTag cheks whether diagnostic has the specified tag
func (sd *SecurityDiagnostic) HasTag(tag string) bool {
	if sd.Tags == nil {
		return false
	}
	for _, t := range *sd.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

//TODO this does not currently work well as expected
func (sd *SecurityDiagnostic) GetValue() string {

	// if sd.Location != nil {
	// 	log.Printf("Location:%s\n", *sd.Location)
	// 	if file, err := os.Open(*sd.Location); err == nil {
	// 		defer file.Close()
	// 		file.Seek(sd.RawRange.StartIndex, io.SeekStart)
	// 		buf := make([]byte, sd.RawRange.EndIndex-sd.RawRange.StartIndex)
	// 		if _, err = file.ReadAt(buf, sd.RawRange.StartIndex); err == nil {
	// 			val := string(buf)
	// 			fmt.Printf("Value:%s\n", val)
	// 			return val
	// 		} else {
	// 			log.Printf("%v\n", err)
	// 		}
	// 	} else {
	// 		log.Printf("%v\n", err)
	// 	}
	// }
	// return ""

	if sd.Source == nil {
		return ""
	}

	return *sd.Source

	// if sd.Source == nil || *sd.Source == "" {
	// 	return ""
	// }

	// lines := strings.Split(*sd.Source, "\n")

	// r := sd.Range
	// hr := sd.HighlightRange

	// begin := int(hr.Start.Character)

	// if hr.Start.Line == r.Start.Line {
	// 	begin -= int(r.Start.Character)
	// } else {
	// 	lineDiff := hr.Start.Line - r.Start.Line
	// 	for i, l := range lines {
	// 		if i < int(lineDiff) {
	// 			begin += len(l) + 1 //+1 is the newline character
	// 		}
	// 	}
	// }

	// end := int(hr.End.Character) //end index not inclusive

	// if hr.End.Line == r.Start.Line {
	// 	end -= int(r.Start.Character)
	// } else {
	// 	lineDiff := hr.End.Line - r.Start.Line
	// 	for i, l := range lines {
	// 		if i < int(lineDiff) {
	// 			end += len(l) + 1 //+1 is the newline character
	// 		}
	// 	}
	// }

	// if begin > end || begin >= len(*sd.Source) {
	// 	//calculation is wrong somewhere, return everything
	// 	return *sd.Source
	// }

	// if end >= len(*sd.Source) {
	// 	//the index is broken. return till the end
	// 	return (*sd.Source)[begin:]
	// }

	// return (*sd.Source)[begin:end]
}

//AddTag adds a tag to the diagnostic
func (sd *SecurityDiagnostic) AddTag(tag string) {
	if sd.Tags == nil {
		sd.Tags = &[]string{tag}
	} else {
		*sd.Tags = append(*sd.Tags, tag)
	}
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

//CharRange describes the location in the file where a range of "text" is found
type CharRange struct {
	StartIndex, EndIndex int64
}

//Confidence reflects the degree of confidence that we have in an assessment
type Confidence int

const (
	//informational Confidence in the assessment
	Info Confidence = iota
	//Low Confidence in the assessment
	Low
	//Medium Confidence in the assessment
	Medium
	//High Confidence in the assessment
	High
	//Critical Confidence in the assessment
	Critical
)

func (conf Confidence) String() string {
	switch conf {
	case Info:
		return "Info"
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Critical:
		return "Critical"
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

//UnmarshalJSON unmarshals a string representation of the confidence to Confidence
func (conf *Confidence) UnmarshalJSON(data []byte) error {
	cc := strings.Trim(string(data), `"`)
	switch cc {
	case Info.String():
		*conf = Info
	case Low.String():
		*conf = Low
	case Medium.String():
		*conf = Medium
	case High.String():
		*conf = High
	case Critical.String():
		*conf = Critical
	default:
		return fmt.Errorf(`unknown confidence type: %s`, cc)
	}
	return nil
}

//Evidence is an atomic piece of information that describes a security diagnostics
type Evidence struct {
	Description string     `json:"description"`
	Confidence  Confidence `json:"confidence"`
}

//Justification describes why a piece of security diagnostic has been generated
type Justification struct {
	Headline Evidence   `json:"headline,omitempty"` //Headline evidence
	Reasons  []Evidence `json:"reasons,omitempty"`  //sub-reasons that justify why this is an issue
}

//SecurityDiagnosticsProvider interface for security diagnostics providers
type SecurityDiagnosticsProvider interface {
	//AddConsumers adds consumers to be notified by this provider when there is a new diagnostics
	AddConsumers(consumers ...SecurityDiagnosticsConsumer)
	Broadcast(diagnostic *SecurityDiagnostic)
}

//SecurityDiagnosticsConsumer is an interface with a callback to receive security diagnostics
type SecurityDiagnosticsConsumer interface {
	ReceiveDiagnostic(diagnostic *SecurityDiagnostic)
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
func (sdp *DefaultSecurityDiagnosticsProvider) Broadcast(diagnostics *SecurityDiagnostic) {
	//ensure that the source, if provided, is converted to UTF-8
	if diagnostics.Source != nil {
		r := transform.NewReader(bytes.NewBufferString(*diagnostics.Source), unicode.UTF8.NewDecoder())
		data, err := ioutil.ReadAll(r)
		if err != nil {
			log.Println(err)
		} else {
			*diagnostics.Source = string(data)
		}
	}

	for _, c := range sdp.consumers {
		c.ReceiveDiagnostic(diagnostics)
	}
}
