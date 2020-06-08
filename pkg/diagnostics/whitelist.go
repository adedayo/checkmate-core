package diagnostics

import (
	"regexp"
)

//WhitelistProvider implements a whitelist strategy
type WhitelistProvider interface {
	//ShouldWhitelist determines whether the supplied value should be whitelisted based on its value and the
	//path (if any) of the source file providing additional context
	ShouldWhitelist(pathContext, value string) bool
	ShouldWhitelistPath(path string) bool
	ShouldWhitelistValue(value string) bool
}

// WhitelistDefinition describes whitelist rules
type WhitelistDefinition struct {
	//These specify regular expressions of matching strings that should be ignored as secrets anywhere they are found
	GloballyExcludedRegExs []string `yaml:"GloballyExcludedRegExs,omitempty"`
	//These specify strings that should be ignored as secrets anywhere they are found
	GloballyExcludedStrings []string `yaml:"GloballyExcludedStrings,omitempty"`
	//These specify regular expression that ignore files whose paths match
	PathExclusionRegExs []string `yaml:"PathExclusionRegExs,omitempty"`
	//These specify sets of strings that should be excluded in a given file. That is filepath -> Set(strings)
	PerFileExcludedStrings map[string][]string `yaml:"PerFileExcludedStrings,omitempty"`
	//These specify sets of regular expressions that if matched on a path matched by the filepath key should be ignored. That is filepath_regex -> Set(regex)
	//This is a quite versatile construct and can model the four above
	PathRegexExcludedRegExs map[string][]string `yaml:"PathRegexExcludedRegex,omitempty"`
}

//defaultWhitelistProvider contains various mechanisms for excluding false positives
type defaultWhitelistProvider struct {
	*WhitelistDefinition
	globallyExcludedRegExsCompiled  []*regexp.Regexp
	pathExclusionRegExsCompiled     []*regexp.Regexp
	pathRegexExcludedRegExsCompiled map[*regexp.Regexp][]*regexp.Regexp
}

//CompileWhitelists returns a WhitelistProvider with the regular expressions already compiled
func CompileWhitelists(whitelist *WhitelistDefinition) (WhitelistProvider, error) {
	wl := defaultWhitelistProvider{
		WhitelistDefinition: whitelist,
	}
	err := wl.compileRegExs()
	if err != nil {
		return nil, err
	}

	return &wl, nil
}

//MakeEmptyWhitelists creates an empty default whitelist
func MakeEmptyWhitelists() WhitelistProvider {
	return &defaultWhitelistProvider{
		WhitelistDefinition: &WhitelistDefinition{
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
func (wl *defaultWhitelistProvider) compileRegExs() error {
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

//ShouldWhitelist determines whether the supplied value should be whitelisted based on its value and the
//path (if any) of the source file providing additional context
func (wl *defaultWhitelistProvider) ShouldWhitelist(pathContext, value string) bool {
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

	return false
}

//ShouldWhitelistPath determines whether the path should be excluded from analysis
func (wl *defaultWhitelistProvider) ShouldWhitelistPath(pathContext string) bool {

	for _, prx := range wl.pathExclusionRegExsCompiled {
		if prx.MatchString(pathContext) {
			return true
		}
	}

	return false
}

//ShouldWhitelistValue determines whether the value should be excluded from results
func (wl *defaultWhitelistProvider) ShouldWhitelistValue(value string) bool {

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
