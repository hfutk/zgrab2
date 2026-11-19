// Package webclassify implements response fingerprint classification for the
// zgrab2 http module.
//
// It labels HTTP responses as direct business web applications or as one of
// the common non-business page types:
//
//	proxy   - authentication-required / open HTTP proxies (407, Squid, ...)
//	cdn     - CDN edge notice pages ("domain not configured", Cloudflare, ...)
//	waf     - cloud WAF block / challenge pages (Aliyun, Safedog, ...)
//	default - middleware default pages (nginx, Apache, IIS, Tomcat, ...)
//	panel   - admin panels (BT-Panel, phpMyAdmin, ...)
//	device  - device / VPN portals (SSL VPN, router UIs, ...)
//	business - no fingerprint matched: presumed direct business web app
//
// Classification only attaches a label to the result. zgrab2 has no concept
// of dropping targets, so the verdict never changes the scan status — pick
// the labels you want downstream, e.g.
//
//	jq 'select(.data.http.classification.category=="business")'.
//
// Rules combine status-code, header, <title> and body regex fingerprints and
// are evaluated in order, first match wins. The rule schema and the built-in
// rule set are ported 1:1 from the standalone web_filter.py tool, so JSON
// rule files written for that tool work unmodified via --classify-web-rules.
package webclassify

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// Category classifies what kind of endpoint produced a response.
type Category string

const (
	CategoryProxy    Category = "proxy"    // auth-required / open HTTP proxies
	CategoryCDN      Category = "cdn"      // CDN edge & "domain not configured" pages
	CategoryWAF      Category = "waf"      // cloud WAF block / challenge pages
	CategoryDefault  Category = "default"  // middleware default pages
	CategoryPanel    Category = "panel"    // admin panels
	CategoryDevice   Category = "device"   // devices / VPN portals
	CategoryBusiness Category = "business" // no fingerprint matched: presumed direct business web app
)

// headerCond is a compiled header condition: the named header must be present
// and, if re is non-nil, its value (comma-joined across duplicates) must
// match re. A pattern of "*" (or the empty string) checks presence only.
type headerCond struct {
	name string
	re   *regexp.Regexp
}

// Rule is a single fingerprint rule. The JSON tags define the rules-file
// schema shared with web_filter.py: a file is either a bare JSON array of
// rules or an object with a "rules" (or "rule" / "data") key.
type Rule struct {
	Name     string            `json:"name"`
	Category Category          `json:"category"`
	Reason   string            `json:"reason"`
	Status   []int             `json:"status,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Title    []string          `json:"title,omitempty"`
	Body     []string          `json:"body,omitempty"`
	Match    string            `json:"match,omitempty"`  // "any" (default) | "all"
	Source   string            `json:"source,omitempty"` // "builtin" or rules-file path

	// compiled forms (not serialized)
	statusSet   map[int]bool
	headerConds []headerCond
	titleRes    []*regexp.Regexp
	bodyRes     []*regexp.Regexp
	matchAll    bool
}

// Options controls how a Classifier is built.
type Options struct {
	// RulesFiles are extra JSON rule files, appended after the builtin
	// rules (unless NoBuiltinRules is set).
	RulesFiles []string
	// NoBuiltinRules disables the builtin rule set.
	NoBuiltinRules bool
}

// Classifier is a compiled, ordered rule set.
type Classifier struct {
	rules []*Rule
}

// Result is the classification label attached to the http module's
// Results when --classify-web is enabled. It is pure metadata: it never
// changes the scan status, it only lets downstream tooling select or
// exclude categories.
type Result struct {
	// Matched reports whether any fingerprint rule matched.
	Matched bool `json:"matched"`
	// Category is the classification label: the first matching rule's
	// category, or "business" when no rule matched (presumed direct
	// business web application).
	Category Category `json:"category"`
	// Rule and Reason identify the first matching rule (empty when no
	// rule matched).
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// GetHeaderFunc returns the value(s) of the named (already lower-cased)
// header, joined with ", " when the header appears multiple times, and
// whether the header was present at all.
type GetHeaderFunc func(name string) (string, bool)

// New compiles a Classifier from the given options.
func New(opts *Options) (*Classifier, error) {
	if opts == nil {
		opts = &Options{}
	}
	f := &Classifier{}

	if !opts.NoBuiltinRules {
		for i := range builtinRules {
			r, err := compileRule(&builtinRules[i], "builtin")
			if err != nil {
				return nil, fmt.Errorf("builtin rule %s: %w", builtinRules[i].Name, err)
			}
			f.rules = append(f.rules, r)
		}
	}
	for _, path := range opts.RulesFiles {
		rules, err := LoadRulesFile(path)
		if err != nil {
			return nil, err
		}
		for i := range rules {
			r, err := compileRule(&rules[i], path)
			if err != nil {
				return nil, fmt.Errorf("%s: rule %s: %w", path, rules[i].Name, err)
			}
			f.rules = append(f.rules, r)
		}
	}
	return f, nil
}

// Classify evaluates the rule set against a response and returns the label
// for the first matching rule (rules are ordered; first match wins), or the
// "business" label when no rule matched. The body is expected to be the
// charset-decoded response body text; bodies that are not valid UTF-8
// (typically raw GBK) are decoded as GBK automatically.
func (f *Classifier) Classify(statusCode int, getHeader GetHeaderFunc, bodyText string) *Result {
	body := NormalizeBody(bodyText)
	title := ExtractTitle(body)
	for _, r := range f.rules {
		if r.matches(statusCode, getHeader, title, body) {
			return &Result{
				Matched:  true,
				Category: r.Category,
				Rule:     r.Name,
				Reason:   r.Reason,
			}
		}
	}
	return &Result{Matched: false, Category: CategoryBusiness}
}

// Rules returns the active rules in their JSON-serializable form, suitable
// for --classify-web-dump-rules output.
func (f *Classifier) Rules() []Rule {
	out := make([]Rule, 0, len(f.rules))
	for _, r := range f.rules {
		out = append(out, *r)
	}
	return out
}

// LoadRulesFile reads a rules JSON file: either a bare JSON array of rules
// or an object with a "rules", "rule" or "data" key holding the array (the
// same schema web_filter.py accepts).
func LoadRulesFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("web classification: could not read rules file %s: %w", path, err)
	}
	var arr []Rule
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	var obj struct {
		Rules []Rule `json:"rules"`
		Rule  []Rule `json:"rule"`
		Data  []Rule `json:"data"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("web classification: rules file %s: expected a JSON array of rules or an object with a \"rules\" key: %w", path, err)
	}
	switch {
	case obj.Rules != nil:
		return obj.Rules, nil
	case obj.Rule != nil:
		return obj.Rule, nil
	case obj.Data != nil:
		return obj.Data, nil
	}
	return nil, fmt.Errorf("web classification: rules file %s: no rules found", path)
}

// SplitList splits a comma-separated flag value into trimmed, non-empty
// parts ("a, b,,c" -> ["a","b","c"]). An empty input yields nil.
func SplitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeCategory(c string) Category {
	return Category(strings.ToLower(strings.TrimSpace(c)))
}

// compileRule validates a raw rule and fills in its compiled forms. The
// original rule is not modified; a compiled copy is returned.
func compileRule(raw *Rule, source string) (*Rule, error) {
	r := *raw
	r.Source = source
	r.Name = strings.TrimSpace(raw.Name)
	if r.Name == "" {
		r.Name = "unnamed"
	}
	r.Category = normalizeCategory(string(raw.Category))
	if r.Category == "" {
		r.Category = "other"
	}
	if strings.TrimSpace(raw.Reason) == "" {
		r.Reason = "自定义规则命中"
	}

	r.statusSet = make(map[int]bool, len(raw.Status))
	for _, s := range raw.Status {
		r.statusSet[s] = true
	}
	for k, v := range raw.Headers {
		name := strings.ToLower(strings.TrimSpace(k))
		pat := strings.TrimSpace(v)
		var re *regexp.Regexp
		if pat != "" && pat != "*" {
			var err error
			if re, err = compileInsensitive(pat); err != nil {
				return nil, fmt.Errorf("header %q: invalid regex %q: %w", k, pat, err)
			}
		}
		r.headerConds = append(r.headerConds, headerCond{name: name, re: re})
	}
	for _, p := range raw.Title {
		re, err := compileInsensitive(p)
		if err != nil {
			return nil, fmt.Errorf("title: invalid regex %q: %w", p, err)
		}
		r.titleRes = append(r.titleRes, re)
	}
	for _, p := range raw.Body {
		re, err := compileInsensitive(p)
		if err != nil {
			return nil, fmt.Errorf("body: invalid regex %q: %w", p, err)
		}
		r.bodyRes = append(r.bodyRes, re)
	}
	r.matchAll = strings.EqualFold(strings.TrimSpace(raw.Match), "all")
	return &r, nil
}

// compileInsensitive compiles a web_filter.py-style pattern: case-insensitive
// search (Python re.I), which is exactly (?i) + pattern in Go's RE2.
func compileInsensitive(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(`(?i)` + pattern)
}

// matches applies the rule to a response. Groups (status, headers, title,
// body) are evaluated like web_filter.py: within the headers / title / body
// groups any single condition counts; match=all requires every non-empty
// group to hit, match=any (default) requires at least one.
func (r *Rule) matches(statusCode int, getHeader GetHeaderFunc, title, body string) bool {
	var groups []bool
	if len(r.statusSet) > 0 {
		groups = append(groups, r.statusSet[statusCode])
	}
	if len(r.headerConds) > 0 {
		hit := false
		for _, hc := range r.headerConds {
			if val, ok := getHeader(hc.name); ok && (hc.re == nil || hc.re.MatchString(val)) {
				hit = true
				break
			}
		}
		groups = append(groups, hit)
	}
	if len(r.titleRes) > 0 {
		hit := false
		for _, re := range r.titleRes {
			if re.MatchString(title) {
				hit = true
				break
			}
		}
		groups = append(groups, hit)
	}
	if len(r.bodyRes) > 0 {
		hit := false
		for _, re := range r.bodyRes {
			if re.MatchString(body) {
				hit = true
				break
			}
		}
		groups = append(groups, hit)
	}
	if len(groups) == 0 {
		return false
	}
	if r.matchAll {
		for _, g := range groups {
			if !g {
				return false
			}
		}
		return true
	}
	for _, g := range groups {
		if g {
			return true
		}
	}
	return false
}

// NormalizeBody decodes bodies that are not valid UTF-8 (typically GBK /
// GB2312, common on Chinese WAF and CDN pages) so that the UTF-8 rule
// patterns match. Valid UTF-8 input is returned unchanged; undecodable
// input is returned as-is.
func NormalizeBody(body string) string {
	if body == "" || utf8.ValidString(body) {
		return body
	}
	if decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes([]byte(body)); err == nil {
		if s := string(decoded); utf8.ValidString(s) {
			return s
		}
	}
	return body
}

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	tagRe   = regexp.MustCompile(`<[^>]+>`)
	wsRe    = regexp.MustCompile(`[ \t\r\n]+`)
)

// ExtractTitle returns the page <title> with inner tags stripped, HTML
// entities unescaped and whitespace collapsed, capped at 200 characters
// (same normalization as web_filter.py).
func ExtractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := html.UnescapeString(tagRe.ReplaceAllString(m[1], " "))
	t = wsRe.ReplaceAllString(t, " ")
	t = strings.TrimSpace(t)
	if runes := []rune(t); len(runes) > 200 {
		t = string(runes[:200])
	}
	return t
}
