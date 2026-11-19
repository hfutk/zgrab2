package webfilter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// headers builds a GetHeaderFunc from a map of lower-cased header names.
func headers(h map[string]string) GetHeaderFunc {
	return func(name string) (string, bool) {
		v, ok := h[name]
		return v, ok
	}
}

func mustFilter(t *testing.T, opts *Options) *Filter {
	t.Helper()
	f, err := New(opts)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return f
}

type classifyCase struct {
	name       string
	opts       *Options
	statusCode int
	headers    map[string]string
	body       string

	wantFiltered bool
	wantCategory Category
	wantRule     string
	wantDropped  bool
}

func runClassifyCases(t *testing.T, cases []classifyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := mustFilter(t, tc.opts)
			res := f.Classify(tc.statusCode, headers(tc.headers), tc.body)
			if res.Filtered != tc.wantFiltered {
				t.Fatalf("Filtered = %v, want %v (got %+v)", res.Filtered, tc.wantFiltered, res)
			}
			if !tc.wantFiltered {
				return
			}
			if res.Category != tc.wantCategory || res.Rule != tc.wantRule || res.Dropped != tc.wantDropped {
				t.Fatalf("got category=%s rule=%s dropped=%v, want category=%s rule=%s dropped=%v",
					res.Category, res.Rule, res.Dropped, tc.wantCategory, tc.wantRule, tc.wantDropped)
			}
		})
	}
}

func TestClassifyBuiltinRules(t *testing.T) {
	runClassifyCases(t, []classifyCase{
		{
			name: "business page stays", statusCode: 200,
			headers: map[string]string{"server": "Apache"},
			body:    "<html><head><title>某公司官方门户 - 登录</title></head><body>欢迎使用我们的业务系统</body></html>",
		},
		{
			name: "empty 200 stays", statusCode: 200, body: "",
		},
		{
			name: "407 proxy", statusCode: 407,
			headers:      map[string]string{"proxy-authenticate": "Basic realm=\"proxy\""},
			body:         "Proxy authentication required",
			wantFiltered: true, wantCategory: CategoryProxy, wantRule: "http_407", wantDropped: true,
		},
		{
			name: "proxy auth header only", statusCode: 200,
			headers:      map[string]string{"proxy-authenticate": "Basic realm=x"},
			wantFiltered: true, wantCategory: CategoryProxy, wantRule: "proxy_auth_header", wantDropped: true,
		},
		{
			name: "squid page", statusCode: 403,
			headers:      map[string]string{"server": "squid/3.5.20", "mime-version": "1.0"},
			body:         "<title>ERROR: Cache Access Denied</title> While trying to retrieve the URL: cache access denied",
			wantFiltered: true, wantCategory: CategoryProxy, wantRule: "squid_proxy", wantDropped: true,
		},
		{
			name: "cloudflare headers", statusCode: 403,
			headers:      map[string]string{"server": "cloudflare", "cf-ray": "8abc123"},
			body:         "Attention Required! | Cloudflare",
			wantFiltered: true, wantCategory: CategoryCDN, wantRule: "cloudflare", wantDropped: true,
		},
		{
			name: "cloudfront bad request", statusCode: 400,
			headers:      map[string]string{"x-amz-cf-id": "abc", "x-cache": "Error from cloudfront"},
			body:         "The request could not be satisfied.",
			wantFiltered: true, wantCategory: CategoryCDN, wantRule: "cloudfront", wantDropped: true,
		},
		{
			name: "cdn domain not configured", statusCode: 200,
			body:         "<title>欢迎访问</title>欢迎使用腾讯云CDN，该域名尚未接入",
			wantFiltered: true, wantCategory: CategoryCDN, wantRule: "cn_cdn", wantDropped: true,
		},
		{
			name: "aliyun waf", statusCode: 405,
			body:         "<html><body>您的请求可能对网站造成威胁，已被Web应用防火墙拦截 errors.aliyun.com</body></html>",
			wantFiltered: true, wantCategory: CategoryWAF, wantRule: "aliyun_waf", wantDropped: true,
		},
		{
			name: "generic waf block", statusCode: 403,
			body:         "<title>请求被拦截</title><body>该请求疑似攻击行为，已触发安全防护</body>",
			wantFiltered: true, wantCategory: CategoryWAF, wantRule: "generic_waf_block", wantDropped: true,
		},
		{
			name: "nginx default page", statusCode: 200,
			body:         "<html><head><title>Welcome to nginx!</title></head><body>If you see this page, the nginx web server is successfully installed</body></html>",
			wantFiltered: true, wantCategory: CategoryDefault, wantRule: "nginx_default", wantDropped: true,
		},
		{
			name: "index of directory listing", statusCode: 200,
			body:         "<html><head><title>Index of /</title></head></html>",
			wantFiltered: true, wantCategory: CategoryDefault, wantRule: "dir_index", wantDropped: true,
		},
		{
			// waf rules run before device rules (same order as web_filter.py):
			// F5 BIG-IP belongs to waf/f5_asm, not device/ssl_vpn.
			name: "f5 block page goes to waf", statusCode: 403,
			body:         "The requested URL was rejected. Please consult with your administrator. Your Support ID is: 12345",
			wantFiltered: true, wantCategory: CategoryWAF, wantRule: "f5_asm", wantDropped: true,
		},
	})
}

func TestPanelAndDeviceKeptByDefault(t *testing.T) {
	runClassifyCases(t, []classifyCase{
		{
			name: "bt panel kept by default", statusCode: 200,
			body:         "<title>宝塔Linux面板 - 登录</title>BT-Panel",
			wantFiltered: true, wantCategory: CategoryPanel, wantRule: "bt_panel", wantDropped: false,
		},
		{
			name: "phpmyadmin kept by default", statusCode: 200,
			body:         "<title>phpMyAdmin</title>",
			wantFiltered: true, wantCategory: CategoryPanel, wantRule: "db_admin_panel", wantDropped: false,
		},
		{
			name: "ssl vpn kept by default", statusCode: 200,
			body:         "<title>SSL VPN</title>EasyConnect",
			wantFiltered: true, wantCategory: CategoryDevice, wantRule: "ssl_vpn", wantDropped: false,
		},
		{
			name: "hikvision camera kept by default", statusCode: 200,
			body:         "Hikvision Digital Technology 网络摄像机",
			wantFiltered: true, wantCategory: CategoryDevice, wantRule: "camera_dvr", wantDropped: false,
		},
	})
}

func TestDropAndKeepOverrides(t *testing.T) {
	runClassifyCases(t, []classifyCase{
		{
			name:         "panel dropped when listed",
			opts:         &Options{DropCategories: []string{"proxy", "cdn", "waf", "default", "panel"}},
			body:         "<title>宝塔Linux面板</title>",
			wantFiltered: true, wantCategory: CategoryPanel, wantRule: "bt_panel", wantDropped: true,
		},
		{
			name:         "device dropped when listed",
			opts:         &Options{DropCategories: []string{"device"}},
			body:         "<title>SSL VPN</title>",
			wantFiltered: true, wantCategory: CategoryDevice, wantRule: "ssl_vpn", wantDropped: true,
		},
		{
			name:         "keep overrides drop",
			opts:         &Options{DropCategories: []string{"proxy", "cdn", "waf", "default"}, KeepCategories: []string{"default"}},
			body:         "<title>Welcome to nginx!</title>",
			wantFiltered: true, wantCategory: CategoryDefault, wantRule: "nginx_default", wantDropped: false,
		},
		{
			name:         "empty drop list keeps everything",
			opts:         &Options{DropCategories: []string{}},
			body:         "Your request was blocked errors.aliyun.com",
			wantFiltered: true, wantCategory: CategoryWAF, wantRule: "aliyun_waf", wantDropped: false,
		},
	})
}

func TestCustomRulesFile(t *testing.T) {
	dir := t.TempDir()
	custom := `[{"name":"my_login_gate","category":"panel","reason":"内部统一登录","status":[200],"body":["sso.example-corp.internal"]}]`
	barePath := filepath.Join(dir, "bare.json")
	if err := os.WriteFile(barePath, []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	wrappedPath := filepath.Join(dir, "wrapped.json")
	if err := os.WriteFile(wrappedPath, []byte(`{"rules":`+custom+`}`), 0o644); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(dir, "bad_regex.json")
	if err := os.WriteFile(badPath, []byte(`[{"name":"bad","category":"waf","reason":"x","body":["("]}]`), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{"bare array": barePath, "wrapped object": wrappedPath} {
		f := mustFilter(t, &Options{RulesFiles: []string{path}})
		res := f.Classify(200, headers(nil), "please sign in via sso.example-corp.internal to continue")
		if !res.Filtered || res.Rule != "my_login_gate" || res.Category != CategoryPanel {
			t.Fatalf("%s: got %+v", name, res)
		}
	}

	// builtin + custom: custom rules run after the builtin set
	f := mustFilter(t, &Options{RulesFiles: []string{barePath}})
	if res := f.Classify(200, headers(nil), "<title>Welcome to nginx!</title>"); res.Rule != "nginx_default" {
		t.Fatalf("builtin rules should still run first, got %+v", res)
	}

	// invalid regex must be rejected at compile time
	if _, err := New(&Options{RulesFiles: []string{badPath}}); err == nil {
		t.Fatal("expected error for invalid regex in rules file")
	}

	// no-builtin: only custom rules run. The custom rule needs status=200
	// and/or the sso body, so a 404 nginx-looking response matches nothing.
	f = mustFilter(t, &Options{RulesFiles: []string{barePath}, NoBuiltinRules: true})
	if res := f.Classify(404, headers(nil), "<title>Welcome to nginx!</title>"); res.Filtered {
		t.Fatalf("builtin rules should be disabled, got %+v", res)
	}
}

func TestMatchAllSemantics(t *testing.T) {
	f := mustFilter(t, &Options{NoBuiltinRules: true, RulesFiles: mustWriteRules(t, []Rule{{
		Name:     "both_required",
		Category: CategoryWAF,
		Reason:   "status and body together",
		Status:   []int{403},
		Body:     []string{"blocked"},
		Match:    "all",
	}})})
	if res := f.Classify(403, headers(nil), "you are blocked"); !res.Filtered {
		t.Fatalf("status+body both hit should match: %+v", res)
	}
	if res := f.Classify(403, headers(nil), "hello world"); res.Filtered {
		t.Fatalf("body missing should not match with match=all: %+v", res)
	}
	if res := f.Classify(200, headers(nil), "you are blocked"); res.Filtered {
		t.Fatalf("status missing should not match with match=all: %+v", res)
	}
}

func mustWriteRules(t *testing.T, rules []Rule) []string {
	t.Helper()
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return []string{path}
}

func TestNormalizeBodyGBK(t *testing.T) {
	// Real-world Chinese WAF pages are often GBK-encoded; the http module's
	// charset sniffer usually decodes them, but when it does not, the filter
	// falls back to GBK decoding itself.
	utf8Body := "您的请求可能对网站造成威胁，已被Web应用防火墙拦截"
	gbkBytes, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(utf8Body))
	if err != nil {
		t.Fatalf("encode GBK: %v", err)
	}
	raw := string(gbkBytes) // intentionally invalid UTF-8, like an undecoded body
	if NormalizeBody(raw) != utf8Body {
		t.Fatalf("GBK body was not normalized")
	}
	if NormalizeBody(utf8Body) != utf8Body {
		t.Fatalf("UTF-8 body should pass through unchanged")
	}

	f := mustFilter(t, nil)
	res := f.Classify(405, headers(nil), raw)
	if !res.Filtered || res.Rule != "aliyun_waf" {
		t.Fatalf("GBK-encoded WAF page not matched: %+v", res)
	}
}

func TestExtractTitle(t *testing.T) {
	cases := map[string]string{
		"<html><head><title>Hello   \n World</title></head>": "Hello World",
		"<title>  Foo &amp; Bar  </title>":                   "Foo & Bar",
		"<title id=\"x\">Tag <b>inside</b> title</title>":    "Tag inside title",
		"<TITLE>Upper Case</TITLE>":                          "Upper Case",
		"no title at all":                                    "",
		"<title>" + strings.Repeat("长", 300) + "</title>":    strings.Repeat("长", 200),
	}
	for body, want := range cases {
		if got := ExtractTitle(body); got != want {
			t.Errorf("ExtractTitle(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestRulesDumpRoundTrip(t *testing.T) {
	f := mustFilter(t, nil)
	rules := f.Rules()
	if len(rules) != 43 {
		t.Fatalf("expected 43 builtin rules (same as web_filter.py), got %d", len(rules))
	}
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	// The dump must be re-loadable via LoadRulesFile semantics (bare array).
	var reloaded []Rule
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dump.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	f2 := mustFilter(t, &Options{RulesFiles: []string{path}, NoBuiltinRules: true})
	if res := f2.Classify(200, headers(nil), "<title>Welcome to nginx!</title>"); !res.Filtered || res.Rule != "nginx_default" {
		t.Fatalf("dumped rules lost fidelity: %+v", res)
	}
}

func TestSplitList(t *testing.T) {
	got := SplitList(" a, b , ,c ,")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("SplitList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SplitList = %v, want %v", got, want)
		}
	}
	if SplitList("") != nil || SplitList(" , ") != nil {
		t.Fatalf("empty input should yield nil")
	}
}
