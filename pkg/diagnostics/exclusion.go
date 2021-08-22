package diagnostics

import (
	"regexp"
)

//ExclusionProvider implements a exclude strategy
type ExclusionProvider interface {
	//ShouldExclude determines whether the supplied value should be excluded based on its value and the
	//path (if any) of the source file providing additional context
	ShouldExclude(pathContext, value string) bool
	ShouldExcludePath(path string) bool
	ShouldExcludeValue(value string) bool
}

// ExcludeDefinition describes exclude rules
type ExcludeDefinition struct {
	//These specify regular expressions of matching strings that should be ignored as secrets anywhere they are found
	GloballyExcludedRegExs []string `yaml:"GloballyExcludedRegExs"`
	//These specify strings that should be ignored as secrets anywhere they are found
	GloballyExcludedStrings []string `yaml:"GloballyExcludedStrings"`
	//These specify regular expressions that ignore files whose paths match
	PathExclusionRegExs []string `yaml:"PathExclusionRegExs"`
	//These specify sets of strings that should be excluded in a given file. That is filepath -> Set(strings)
	PerFileExcludedStrings map[string][]string `yaml:"PerFileExcludedStrings"`
	//These specify sets of regular expressions that if matched on a path matched by the filepath key should be ignored. That is filepath_regex -> Set(regex)
	//This is a quite versatile construct and can model the four above
	PathRegexExcludedRegExs map[string][]string `yaml:"PathRegexExcludedRegex"`
}

type ExcludeRequirement struct {
	What      string
	Issue     SecurityDiagnostic
	ProjectID string
}

type PolicyUpdateResult struct {
	Status    string
	NewPolicy string
}

//GenerateSampleExclusion generates a sample exclusion YAML file content with descriptions
func GenerateSampleExclusion() string {
	return `# This is a sample Exclusion YAML file to specify patterns of directories, files and values
# to exclude while searching for secrets

# Use GloballyExcludedRegExs to specify regular expressions of matching strings that should be ignored as secrets anywhere they are found
# For example (uncomment the next three lines):
# GloballyExcludedRegExs:
#    - .*keyword.* #ignore any value with the word keyword in it 
#    - .*public.*  #ignore any value with the word public in it 
#

# Use GloballyExcludedStrings to specify strings that should be ignored as secrets anywhere they are found
# For example (uncomment the next three lines):
# GloballyExcludedStrings:
#    - NotAPassword
#    - "Another non-password"
#

# Use PathExclusionRegExs to specify regular expressions that ignore files and directories, which if matched should not be scanned for secrets
# For example (uncomment the next five lines):
# PathExclusionRegExs:
#     - .*/ignore/subpath/.* # ignore files and directories which contain the subpath '/ignore/subpath/' in its name
#     - .*/README.md # ignore the file README.md wherever it may be found
#     - .*/package-lock.json # ignore package-lock.json files wherever they are found
#     - .*[.]html? # ignore all HTML files (ending with extension .html or .htm)


# Use PerFileExcludedStrings to specify strings that should be excluded in a given file (indicated by its full path)
# For example (uncomment the next six lines):
# PerFileExcludedStrings:
#     /home/user/myfile.txt: #file of interest
#         - "ignore this value" # a value to ignore in the file
#         - "another value" # another value to ignore in the file /home/user/myfile.txt
#     "/home/user/second file.txt": #another file of interest
#         - "not interesting" #ignore this value in the file

# PathRegexExcludedRegex is a versatile path/directory and value regular expression-based exclusion config. 
# Use it to simultaneously specify both path and value of non-interest to ignore.
# For example (uncomment the next six lines):
# PathRegexExcludedRegex:
#     .*/ignore/subpath/.*: #ignore all files and directories that have this subpath in their name
#         - .*public_key.* #ignore values that contain the phrase public_key
#         - "not secret" #ignore value 'not secret'
#     .*/keyword/directory/.*: #another path we'd like to target for ignoring certain values
#         - .*keyword.* #ignore any value with the word keyword in it in any file whose path contains subpath '/keyword/directory/'
`
}

//defaultExclusionProvider contains various mechanisms for excluding false positives
type defaultExclusionProvider struct {
	*ExcludeDefinition
	globallyExcludedRegExsCompiled  []*regexp.Regexp
	pathExclusionRegExsCompiled     []*regexp.Regexp
	pathRegexExcludedRegExsCompiled map[*regexp.Regexp][]*regexp.Regexp
}

//CompileExcludes returns a ExclusionProvider with the regular expressions already compiled
func CompileExcludes(exclude *ExcludeDefinition) (ExclusionProvider, error) {
	wl := defaultExclusionProvider{
		ExcludeDefinition: exclude,
	}
	err := wl.compileRegExs()
	if err != nil {
		return nil, err
	}
	return &wl, nil
}

//MakeEmptyExcludes creates an empty default exclusion list
func MakeEmptyExcludes() ExclusionProvider {
	return &defaultExclusionProvider{
		ExcludeDefinition: &ExcludeDefinition{
			GloballyExcludedStrings: []string{},
			GloballyExcludedRegExs:  []string{},
			PathExclusionRegExs:     []string{},
			PathRegexExcludedRegExs: make(map[string][]string),
			PerFileExcludedStrings:  make(map[string][]string),
		},
		globallyExcludedRegExsCompiled:  []*regexp.Regexp{},
		pathExclusionRegExsCompiled:     []*regexp.Regexp{},
		pathRegexExcludedRegExsCompiled: make(map[*regexp.Regexp][]*regexp.Regexp),
	}
}

//compileRegExs ensures the regular expressions defined are compiled before use
func (wl *defaultExclusionProvider) compileRegExs() error {
	wl.globallyExcludedRegExsCompiled = make([]*regexp.Regexp, 0)
	for _, s := range wl.GloballyExcludedRegExs {
		if re, err := regexp.Compile(s); err == nil {
			wl.globallyExcludedRegExsCompiled = append(wl.globallyExcludedRegExsCompiled, re)
		} else {
			return err
		}
	}

	wl.pathExclusionRegExsCompiled = make([]*regexp.Regexp, 0)
	for _, s := range wl.PathExclusionRegExs {
		if re, err := regexp.Compile(s); err == nil {
			wl.pathExclusionRegExsCompiled = append(wl.pathExclusionRegExsCompiled, re)
		} else {
			return err
		}
	}

	wl.pathRegexExcludedRegExsCompiled = make(map[*regexp.Regexp][]*regexp.Regexp)
	for p, ss := range wl.PathRegexExcludedRegExs {
		pre, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		srs := make([]*regexp.Regexp, 0)
		for _, s := range ss {
			sre, err := regexp.Compile(s)
			if err != nil {
				return err
			}
			srs = append(srs, sre)
		}
		wl.pathRegexExcludedRegExsCompiled[pre] = srs
	}
	return nil
}

//ShouldExclude determines whether the supplied value should be excluded based on its value and the
//path (if any) of the source file providing additional context
func (wl *defaultExclusionProvider) ShouldExclude(pathContext, value string) bool {
	// fmt.Printf("Should exclude Path:%s, Value:%s\n", pathContext, value)
	for _, s := range wl.GloballyExcludedStrings {
		if s == value {
			return true
		}
	}

	for p, mvs := range wl.PerFileExcludedStrings {
		if p == pathContext {
			for _, mv := range mvs {
				if value == mv {
					return true
				}
			}
		}
	}

	for _, prx := range wl.pathExclusionRegExsCompiled {
		if prx.MatchString(pathContext) {
			return true
		}
	}

	for _, rx := range wl.globallyExcludedRegExsCompiled {
		if rx.MatchString(value) {
			return true
		}
	}

	for prx, rxs := range wl.pathRegexExcludedRegExsCompiled {
		if prx.MatchString(pathContext) {
			for _, rx := range rxs {
				if rx.MatchString(value) {
					return true
				}
			}
		}
	}
	return false
}

//ShouldExcludePath determines whether the path should be excluded from analysis
func (wl *defaultExclusionProvider) ShouldExcludePath(pathContext string) bool {

	for _, prx := range wl.pathExclusionRegExsCompiled {
		if prx.MatchString(pathContext) {
			return true
		}
	}

	return false
}

//ShouldExcludeValue determines whether the value should be excluded from results
func (wl *defaultExclusionProvider) ShouldExcludeValue(value string) bool {

	for _, s := range wl.GloballyExcludedStrings {
		if s == value {
			return true
		}
	}

	for _, rx := range wl.globallyExcludedRegExsCompiled {
		if rx.MatchString(value) {
			return true
		}
	}

	return false
}
