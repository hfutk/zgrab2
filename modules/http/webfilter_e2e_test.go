package http

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/http/webfilter"
)

// webFilterTestServer is a minimal HTTP server that answers every connection
// with a canned response, so the full scanner stack (real dialer group,
// lib/http client, body decoding, web filter hook) is exercised.
type webFilterTestServer struct {
	listener net.Listener
	response string
}

func startWebFilterTestServer(t *testing.T, response string) *webFilterTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &webFilterTestServer{listener: ln, response: response}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// consume the request head
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				c.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprint(c, response)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return srv
}

func httpResp(status string, headers []string, body string) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
	b.WriteString(body)
	return b.String()
}

func runWebFilterScan(t *testing.T, flags *Flags, response string) (zgrab2.ScanStatus, *Results) {
	t.Helper()
	srv := startWebFilterTestServer(t, response)
	scanner := NewModule().NewScanner().(*Scanner)
	flags.Port = uint(lport(t, srv.listener.Addr().String()))
	flags.ConnectTimeout = 5 * time.Second
	if err := scanner.Init(flags); err != nil {
		t.Fatalf("scanner.Init: %v", err)
	}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: flags.Port}
	dialerGroup, err := scanner.DialerGroupConfig.GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("dialer group: %v", err)
	}
	status, res, _ := scanner.Scan(context.Background(), dialerGroup, target)
	results, _ := res.(*Results)
	if results == nil {
		t.Fatalf("nil results (status %s)", status)
	}
	return status, results
}

func lport(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	var port int
	fmt.Sscanf(p, "%d", &port)
	return port
}

func baseWebFilterFlags() *Flags {
	f := NewModule().NewFlags().(*Flags)
	// Field defaults from the zflags tags only apply during CLI parsing, so
	// set them explicitly here.
	f.Method = "GET"
	f.Endpoint = "/"
	f.MaxSize = 256
	f.MaxRedirects = 0
	f.UserAgent = "Mozilla/5.0 zgrab/0.x"
	f.WebFilterEnable = true
	return f
}

// requireLabel asserts the core label semantics: whatever the classification
// verdict is, the scan status stays "success" — the web_filter block is pure
// metadata, zgrab2 never drops targets.
func requireLabel(t *testing.T, status zgrab2.ScanStatus, results *Results, matched bool, category webfilter.Category, rule string) {
	t.Helper()
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, want success (classification must never change the scan status)", status)
	}
	wf := results.WebFilter
	if wf == nil {
		t.Fatal("web_filter block missing")
	}
	if wf.Matched != matched {
		t.Fatalf("matched = %v, want %v", wf.Matched, matched)
	}
	if wf.Category != category {
		t.Fatalf("category = %s, want %s", wf.Category, category)
	}
	if matched && wf.Rule != rule {
		t.Fatalf("rule = %s, want %s", wf.Rule, rule)
	}
}

func TestWebFilterScanBusinessPage(t *testing.T) {
	status, results := runWebFilterScan(t, baseWebFilterFlags(),
		httpResp("200 OK", nil, "<html><head><title>某公司业务系统</title></head><body>登录</body></html>"))
	requireLabel(t, status, results, false, webfilter.CategoryBusiness, "")
}

func TestWebFilterScanNginxDefaultLabeled(t *testing.T) {
	status, results := runWebFilterScan(t, baseWebFilterFlags(),
		httpResp("200 OK", []string{"Server: nginx/1.24.0"},
			"<html><head><title>Welcome to nginx!</title></head><body>If you see this page, the nginx web server is successfully installed.</body></html>"))
	// still a successful scan: the default-page verdict is only a label
	requireLabel(t, status, results, true, webfilter.CategoryDefault, "nginx_default")
}

func TestWebFilterScanWAFLabeled(t *testing.T) {
	status, results := runWebFilterScan(t, baseWebFilterFlags(),
		httpResp("405 Not Allowed", nil,
			"<html><body>您的请求可能对网站造成威胁，已被Web应用防火墙拦截 <a href='https://errors.aliyun.com'>errors.aliyun.com</a></body></html>"))
	requireLabel(t, status, results, true, webfilter.CategoryWAF, "aliyun_waf")
}

func TestWebFilterScanProxy407Labeled(t *testing.T) {
	status, results := runWebFilterScan(t, baseWebFilterFlags(),
		httpResp("407 Proxy Authentication Required", []string{"Proxy-Authenticate: Basic realm=\"proxy\""}, "auth pls"))
	requireLabel(t, status, results, true, webfilter.CategoryProxy, "http_407")
}

func TestWebFilterScanPanelLabeled(t *testing.T) {
	status, results := runWebFilterScan(t, baseWebFilterFlags(),
		httpResp("200 OK", nil, "<html><head><title>宝塔Linux面板 - 安全入口</title></head><body>BT-Panel</body></html>"))
	requireLabel(t, status, results, true, webfilter.CategoryPanel, "bt_panel")
}

func TestWebFilterScanCloudflareCDNLabeled(t *testing.T) {
	status, results := runWebFilterScan(t, baseWebFilterFlags(),
		httpResp("403 Forbidden", []string{"Server: cloudflare", "Cf-Ray: 8f3a2b1c0d9e0123-LAX"},
			"<html><body>Attention Required! | Cloudflare<br>Ray ID: 8f3a2b1c0d9e0123</body></html>"))
	requireLabel(t, status, results, true, webfilter.CategoryCDN, "cloudflare")
}

// TestWebFilterScanDisabledByDefault verifies that without --web-filter the
// results carry no web_filter block at all.
func TestWebFilterScanDisabledByDefault(t *testing.T) {
	f := baseWebFilterFlags()
	f.WebFilterEnable = false
	status, results := runWebFilterScan(t, f,
		httpResp("200 OK", nil, "<html><head><title>Welcome to nginx!</title></head></html>"))
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, want success", status)
	}
	if results.WebFilter != nil {
		t.Fatalf("web_filter = %+v, want nil without --web-filter", results.WebFilter)
	}
}
